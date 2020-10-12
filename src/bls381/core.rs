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
use crate::errors::AmclError;
use crate::hash256::HASH256;
use crate::rand::RAND;

// Key Generation Constants
/// Domain for key generation.
pub const KEY_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
/// L = ceil((3 * ceil(log2(r))) / 16) = 48.
pub const KEY_GENERATION_L: u8 = 48;

// Length of objects in bytes
/// The required number of bytes for a secret key
pub const SECRET_KEY_BYTES: usize = 32;
/// The required number of bytes for a compressed G1 point
pub const G1_BYTES: usize = MODBYTES;
/// The required number of bytes for a compressed G2 point
pub const G2_BYTES: usize = MODBYTES * 2;

// Serialization flags
const COMPRESION_FLAG: u8 = 0b_1000_0000;
const INFINITY_FLAG: u8 = 0b_0100_0000;
const Y_FLAG: u8 = 0b_0010_0000;

/// KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
pub(crate) fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    let mut secret_key = Big::new();
    let mut salt = KEY_SALT.to_vec();

    while secret_key.is_zilch() {
        // salt = H(salt)
        let mut hash256 = HASH256::new();
        hash256.init();
        hash256.process_array(&salt);
        salt = hash256.hash().to_vec();

        // PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
        let mut prk = Vec::<u8>::with_capacity(1 + ikm.len());
        prk.extend_from_slice(ikm);
        prk.push(0);
        let prk = HASH256::hkdf_extract(&salt, &prk);

        // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
        let mut info = key_info.to_vec();
        info.extend_from_slice(&[0, KEY_GENERATION_L]);
        let okm = HASH256::hkdf_extend(&prk, &info, KEY_GENERATION_L);

        // SK = OS2IP(OKM) mod r
        let r = Big::new_ints(&CURVE_ORDER);
        secret_key = Big::from_bytes(&okm);
        secret_key.rmod(&r);
    }

    secret_key_to_bytes(&secret_key)
}

// Converts secret key bytes to a Big
pub fn secret_key_from_bytes(secret_key: &[u8]) -> Result<Big, AmclError> {
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(AmclError::InvalidSecretKeySize);
    }

    // Prepend to MODBYTES in length
    let mut secret_key_bytes = [0u8; MODBYTES];
    secret_key_bytes[MODBYTES - SECRET_KEY_BYTES..].copy_from_slice(secret_key);

    // Ensure secret key is in the range [1, r-1].
    let secret_key = Big::from_bytes(&secret_key_bytes);
    if secret_key.is_zilch() || secret_key >= Big::new_ints(&CURVE_ORDER) {
        return Err(AmclError::InvalidSecretKeyRange);
    }

    Ok(secret_key)
}

// Converts secret key Big to bytes
pub fn secret_key_to_bytes(secret_key: &Big) -> [u8; SECRET_KEY_BYTES] {
    let mut big_bytes = [0u8; MODBYTES];
    secret_key.to_bytes(&mut big_bytes);
    let mut secret_key_bytes = [0u8; SECRET_KEY_BYTES];
    secret_key_bytes.copy_from_slice(&big_bytes[MODBYTES - SECRET_KEY_BYTES..]);
    secret_key_bytes
}

// Verifies a G1 point is in subgroup `r`.
pub fn subgroup_check_g1(point: &ECP) -> bool {
    let r = Big::new_ints(&CURVE_ORDER);
    let check = pair::g1mul(&point, &r);
    check.is_infinity()
}

// Verifies a G2 point is in subgroup `r`.
pub fn subgroup_check_g2(point: &ECP2) -> bool {
    let r = Big::new_ints(&CURVE_ORDER);
    let check = pair::g2mul(&point, &r);
    check.is_infinity()
}

// Compare values of two FP2 elements,
// -1 if num1 < num2; 0 if num1 == num2; 1 if num1 > num2
fn zcash_cmp_fp2(num1: &mut FP2, num2: &mut FP2) -> isize {
    // First compare FP2.b
    let mut result = Big::comp(&num1.getb(), &num2.getb());

    // If FP2.b is equal compare FP2.a
    if result == 0 {
        result = Big::comp(&num1.geta(), &num2.geta());
    }
    result
}

/// Take a G1 point (x, y) and compress it to a 48 byte array.
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn serialize_g1(g1: &ECP) -> [u8; G1_BYTES] {
    // Check point at inifinity
    if g1.is_infinity() {
        let mut result = [0u8; G1_BYTES];
        // Set compressed flag and infinity flag
        result[0] = u8::pow(2, 6) + u8::pow(2, 7);
        return result;
    }

    // Convert x-coordinate to bytes
    let mut result = [0u8; G1_BYTES];
    g1.getx().to_bytes(&mut result);

    // Evaluate if y > -y
    let mut tmp = g1.clone();
    tmp.affine();
    let y = tmp.gety();
    tmp.neg();
    let y_neg = tmp.gety();

    // Set flags
    if y > y_neg {
        result[0] += Y_FLAG;
    }
    result[0] += COMPRESION_FLAG;

    result
}

/// Take a G1 point (x, y) and converti it to a 96 byte array.
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn serialize_uncompressed_g1(g1: &ECP) -> [u8; G1_BYTES * 2] {
    // Check point at inifinity
    let mut result = [0u8; G1_BYTES * 2];
    if g1.is_infinity() {
        result[0] = INFINITY_FLAG;
        return result;
    }

    // Convert x-coordinate to bytes
    g1.getx().to_bytes(&mut result[..MODBYTES]);
    g1.gety().to_bytes(&mut result[MODBYTES..]);

    result
}

/// Take a 48 or 96 byte array and convert to a G1 point (x, y)
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn deserialize_g1(g1_bytes: &[u8]) -> Result<ECP, AmclError> {
    if g1_bytes.len() == 0 {
        return Err(AmclError::InvalidG1Size);
    }

    if g1_bytes[0] & COMPRESION_FLAG == 0 {
        deserialize_uncompressed_g1(g1_bytes)
    } else {
        deserialize_compressed_g1(g1_bytes)
    }
}

// Deserialization of a G1 point from x-coordinate
fn deserialize_compressed_g1(g1_bytes: &[u8]) -> Result<ECP, AmclError> {
    // Length must be 48 bytes
    if g1_bytes.len() != G1_BYTES {
        return Err(AmclError::InvalidG1Size);
    }

    // Check infinity flag
    if g1_bytes[0] & INFINITY_FLAG != 0 {
        // Trailing bits should all be 0.
        if g1_bytes[0] & 0b_0011_1111 != 0 {
            return Err(AmclError::InvalidPoint);
        }

        for item in g1_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(AmclError::InvalidPoint);
            }
        }

        return Ok(ECP::new()); // infinity
    }

    let y_flag: bool = (g1_bytes[0] & Y_FLAG) > 0;

    // Zero flags
    let mut g1_bytes = g1_bytes.to_owned();
    g1_bytes[0] = g1_bytes[0] & 0b_0001_1111;
    let x = Big::from_bytes(&g1_bytes);

    // Require element less than field modulus
    let m = Big::new_ints(&MODULUS);
    if x >= m {
        return Err(AmclError::InvalidPoint);
    }

    // Convert to G1 from x-coordinate
    let point = ECP::new_big(&x);
    if point.is_infinity() {
        return Err(AmclError::InvalidPoint);
    }

    // Confirm y value
    let mut point_neg = point.clone();
    point_neg.neg();

    if (point.gety() > point_neg.gety()) != y_flag {
        Ok(point_neg)
    } else {
        Ok(point)
    }
}

// Deserialization of a G1 point from (x, y).
fn deserialize_uncompressed_g1(g1_bytes: &[u8]) -> Result<ECP, AmclError> {
    // Length must be 96 bytes
    if g1_bytes.len() != G1_BYTES * 2 {
        return Err(AmclError::InvalidG1Size);
    }

    // Check infinity flag
    if g1_bytes[0] & INFINITY_FLAG != 0 {
        // Trailing bits should all be 0.
        if g1_bytes[0] & 0b_0011_1111 != 0 {
            return Err(AmclError::InvalidPoint);
        }

        for item in g1_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(AmclError::InvalidPoint);
            }
        }

        return Ok(ECP::new()); // infinity
    }

    // Require y_flag to be zero
    if (g1_bytes[0] & Y_FLAG) > 0 {
        return Err(AmclError::InvalidYFlag);
    }

    // Zero flags
    let mut g1_bytes = g1_bytes.to_owned();
    g1_bytes[0] = g1_bytes[0] & 0b_0001_1111;
    let x = Big::from_bytes(&g1_bytes[..MODBYTES]);
    let y = Big::from_bytes(&g1_bytes[MODBYTES..]);

    // Require elements less than field modulus
    let m = Big::new_ints(&MODULUS);
    if x >= m || y >= m {
        return Err(AmclError::InvalidPoint);
    }

    // Convert to G1
    let point = ECP::new_bigs(&x, &y);
    if point.is_infinity() {
        return Err(AmclError::InvalidPoint);
    }

    Ok(point)
}

/// Take a G2 point (x, y) and compress it to a 96 byte array as the x-coordinate.
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn serialize_g2(g2: &ECP2) -> [u8; G2_BYTES] {
    // Check point at inifinity
    if g2.is_infinity() {
        let mut result = [0; G2_BYTES];
        result[0] += COMPRESION_FLAG + INFINITY_FLAG;
        return result;
    }

    // Convert x-coordinate to bytes
    // Note: Zcash uses (x_im, x_re)
    let mut result = [0u8; G2_BYTES];
    let x = g2.getx();
    x.geta().to_bytes(&mut result[MODBYTES..(MODBYTES * 2)]);
    x.getb().to_bytes(&mut result[0..MODBYTES]);

    // Check y value
    let mut y = g2.gety();
    let mut y_neg = y.clone();
    y_neg.neg();

    // Set flags
    if zcash_cmp_fp2(&mut y, &mut y_neg) > 0 {
        result[0] += Y_FLAG;
    }
    result[0] += COMPRESION_FLAG;

    result
}

/// Take a G2 point (x, y) and convert it to a 192 byte array as (x, y).
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn serialize_uncompressed_g2(g2: &ECP2) -> [u8; G2_BYTES * 2] {
    let mut result = [0; G2_BYTES * 2];

    // Check point at inifinity
    if g2.is_infinity() {
        result[0] += INFINITY_FLAG;
        return result;
    }

    // Convert to bytes
    // Note: Zcash uses (x_im, x_re), (y_im, y_re)
    let x = g2.getx();
    x.getb().to_bytes(&mut result[0..MODBYTES]);
    x.geta().to_bytes(&mut result[MODBYTES..(MODBYTES * 2)]);
    let x = g2.gety();
    x.getb()
        .to_bytes(&mut result[(MODBYTES * 2)..(MODBYTES * 3)]);
    x.geta().to_bytes(&mut result[(MODBYTES * 3)..]);

    result
}

/// Take a 96 or 192 byte array and convert to G2 point (x, y)
///
/// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn deserialize_g2(g2_bytes: &[u8]) -> Result<ECP2, AmclError> {
    if g2_bytes.len() == 0 {
        return Err(AmclError::InvalidG2Size);
    }

    if g2_bytes[0] & COMPRESION_FLAG == 0 {
        deserialize_uncompressed_g2(g2_bytes)
    } else {
        deserialize_compressed_g2(g2_bytes)
    }
}

// Decompress a G2 point from x-coordinate
fn deserialize_compressed_g2(g2_bytes: &[u8]) -> Result<ECP2, AmclError> {
    if g2_bytes.len() != G2_BYTES {
        return Err(AmclError::InvalidG2Size);
    }

    // Check infinity flag
    if g2_bytes[0] & INFINITY_FLAG != 0 {
        // Trailing bits should all be 0.
        if g2_bytes[0] & 0b_0011_1111 != 0 {
            return Err(AmclError::InvalidPoint);
        }
        for item in g2_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(AmclError::InvalidPoint);
            }
        }

        return Ok(ECP2::new()); // infinity
    }

    let y_flag: bool = (g2_bytes[0] & Y_FLAG) > 0;

    // Zero flags
    let mut g2_bytes = g2_bytes.to_owned();
    g2_bytes[0] = g2_bytes[0] & 0b_0001_1111;

    // Convert from array to FP2
    let x_imaginary = Big::from_bytes(&g2_bytes[0..MODBYTES]);
    let x_real = Big::from_bytes(&g2_bytes[MODBYTES..]);

    // Require elements less than field modulus
    let m = Big::new_ints(&MODULUS);
    if x_imaginary >= m || x_real >= m {
        return Err(AmclError::InvalidPoint);
    }
    let x = FP2::new_bigs(x_real, x_imaginary);

    // Convert to G2 from x-coordinate
    let point = ECP2::new_fp2(&x);
    if point.is_infinity() {
        return Err(AmclError::InvalidPoint);
    }

    // Confirm y value
    let mut point_neg = point.clone();
    point_neg.neg();

    if (zcash_cmp_fp2(&mut point.gety(), &mut point_neg.gety()) > 0) != y_flag {
        Ok(point_neg)
    } else {
        Ok(point)
    }
}

// Decompress a G2 point from (x, y)
fn deserialize_uncompressed_g2(g2_bytes: &[u8]) -> Result<ECP2, AmclError> {
    if g2_bytes.len() != G2_BYTES * 2 {
        return Err(AmclError::InvalidG2Size);
    }

    // Check infinity flag
    if g2_bytes[0] & INFINITY_FLAG != 0 {
        // Trailing bits should all be 0.
        if g2_bytes[0] & 0b_0011_1111 != 0 {
            return Err(AmclError::InvalidPoint);
        }
        for item in g2_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(AmclError::InvalidPoint);
            }
        }

        return Ok(ECP2::new()); // infinity
    }

    if (g2_bytes[0] & Y_FLAG) > 0 {
        return Err(AmclError::InvalidYFlag);
    }

    // Zero flags
    let mut g2_bytes = g2_bytes.to_owned();
    g2_bytes[0] = g2_bytes[0] & 0b_0001_1111;

    // Convert from array to FP2
    let x_imaginary = Big::from_bytes(&g2_bytes[..MODBYTES]);
    let x_real = Big::from_bytes(&g2_bytes[MODBYTES..(MODBYTES * 2)]);
    let y_imaginary = Big::from_bytes(&g2_bytes[(MODBYTES * 2)..(MODBYTES * 3)]);
    let y_real = Big::from_bytes(&g2_bytes[(MODBYTES * 3)..]);

    // Require elements less than field modulus
    let m = Big::new_ints(&MODULUS);
    if x_imaginary >= m || x_real >= m || y_imaginary >= m || y_real >= m {
        return Err(AmclError::InvalidPoint);
    }
    let x = FP2::new_bigs(x_real, x_imaginary);
    let y = FP2::new_bigs(y_real, y_imaginary);

    // Convert to G2 from x-coordinate
    let point = ECP2::new_fp2s(x, y);
    if point.is_infinity() {
        return Err(AmclError::InvalidPoint);
    }

    Ok(point)
}

/*************************************************************************************************
* Core BLS Functions when signatures are on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2
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
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.4
pub(crate) fn secret_key_to_public_key_g1(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP2::generator();
    let public_key = pair::g2mul(&g, &secret_key);

    Ok(serialize_g2(&public_key))
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
pub(crate) fn core_sign_g1(
    secret_key: &[u8],
    msg: &[u8],
    dst: &[u8],
) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let hash = hash_to_curve_g1(msg, dst);
    let signature = pair::g1mul(&hash, &secret_key);

    Ok(serialize_g1(&signature))
}

// CoreVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
pub(crate) fn core_verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8], dst: &[u8]) -> bool {
    let public_key = deserialize_g2(public_key);
    let signature = deserialize_g1(signature);

    if public_key.is_err() || signature.is_err() {
        return false;
    }

    let public_key = public_key.unwrap();
    let signature = signature.unwrap();

    // Subgroup checks for signature and public key
    if !subgroup_check_g1(&signature) || !subgroup_check_g2(&public_key) || public_key.is_infinity() {
        return false;
    }

    // Hash msg and negate generator for pairing
    let hash = hash_to_curve_g1(msg, dst);
    let mut g = ECP2::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &signature);
    pair::another(&mut r, &public_key, &hash);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub(crate) fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    let mut aggregate = deserialize_g1(&points[0])?;
    for point in points.iter().skip(1) {
        aggregate.add(&deserialize_g1(&point)?);
    }

    Ok(serialize_g1(&aggregate))
}

// CoreAggregateVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.9
pub(crate) fn core_aggregate_verify_g1(
    public_keys: &[&[u8]],
    msgs: &[&[u8]],
    signature: &[u8],
    dst: &[u8],
) -> bool {
    // Preconditions
    if public_keys.len() == 0 || public_keys.len() != msgs.len() {
        return false;
    }

    let signature = deserialize_g1(signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();

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
        let public_key = deserialize_g2(public_key);
        if public_key.is_err() {
            return false;
        }
        let public_key = public_key.unwrap();

        if !subgroup_check_g2(&public_key) || public_key.is_infinity() {
            return false;
        }

        // Pair *= e(pk[i], H(msgs[i]))
        let hash = hash_to_curve_g1(msgs[i], dst);
        pair::another(&mut r, &public_key, &hash);
    }

    // True if pairing output is 1
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);
    v.is_unity()
}

/*************************************************************************************************
* Core BLS Functions when signatures are on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2
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
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.4
pub(crate) fn secret_key_to_public_key_g2(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP::generator();
    let public_key = pair::g1mul(&g, &secret_key);

    // Convert to bytes
    Ok(serialize_g1(&public_key))
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
pub(crate) fn core_sign_g2(
    secret_key: &[u8],
    msg: &[u8],
    dst: &[u8],
) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;

    let hash = hash_to_curve_g2(msg, dst);
    let signature = pair::g2mul(&hash, &secret_key);

    Ok(serialize_g2(&signature))
}

// CoreVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
pub(crate) fn core_verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8], dst: &[u8]) -> bool {
    let public_key = deserialize_g1(public_key);
    let signature = deserialize_g2(signature);

    if public_key.is_err() || signature.is_err() {
        return false;
    }

    let public_key = public_key.unwrap();
    let signature = signature.unwrap();

    // Subgroup checks for signature and public key
    if !subgroup_check_g1(&public_key) || public_key.is_infinity() || !subgroup_check_g2(&signature) {
        return false;
    }

    // Hash msg and negate generator for pairing
    let hash = hash_to_curve_g2(msg, dst);
    let mut g = ECP::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &signature, &g);
    pair::another(&mut r, &hash, &public_key);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub(crate) fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    let mut aggregate = deserialize_g2(&points[0])?;
    for point in points.iter().skip(1) {
        aggregate.add(&deserialize_g2(&point)?);
    }

    Ok(serialize_g2(&aggregate))
}

// CoreAggregateVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.9
pub(crate) fn core_aggregate_verify_g2(
    public_keys: &[&[u8]],
    msgs: &[&[u8]],
    signature: &[u8],
    dst: &[u8],
) -> bool {
    let signature = deserialize_g2(signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();

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
        let public_key = deserialize_g1(public_key);
        if public_key.is_err() {
            return false;
        }
        let public_key = public_key.unwrap();

        // Subgroup check for public key
        if !subgroup_check_g1(&public_key) || public_key.is_infinity() {
            return false;
        }

        // Pair *= e(pk[i], H(msgs[i]))
        let hash = hash_to_curve_g2(msgs[i], dst);
        pair::another(&mut r, &hash, &public_key);
    }

    // True if pairing output is 1
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);
    v.is_unity()
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on G1
*************************************************************************************************/

/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3
pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> ECP {
    let u =
        hash_to_field_fp(msg, 2, dst).expect("hash to field should not fail for given parameters");
    let mut q0 = map_to_curve_g1(u[0].clone());
    let q1 = map_to_curve_g1(u[1].clone());
    q0.add(&q1);
    let p = q0.mul(&Big::new_ints(&H_EFF_G1));
    p
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// SSWU - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-6.6.2
// ISO11 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#appendix-C.2
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
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3
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
// SSWU - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-6.6.2
// ISO3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#appendix-C.3
fn map_to_curve_g2(u: FP2) -> ECP2 {
    let (x, y) = simplified_swu_fp2(u);
    iso3_to_ecp2(&x, &y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    const TEST_DST: &[u8] = b"BLS_TEST_";

    #[test]
    fn test_hash_to_curve_g2() {
        const H2C_SUITE_G2: &str = "BLS12381G2_XMD:SHA-256_SSWU_RO_";
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
                let a = Big::from_bytes(&hex::decode(&u_str_parts[0].get(2..).unwrap()).unwrap());
                let b = Big::from_bytes(&hex::decode(&u_str_parts[1].get(2..).unwrap()).unwrap());
                let expected_u_i = FP2::new_bigs(a, b);

                // Verify u[i]
                assert_eq!(expected_u_i, u[i]);
            }

            // Check Q0
            let x_str_parts: Vec<&str> = case.Q0.x.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.Q0.y.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_q0 = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_q0, q0);

            // Check Q1
            let x_str_parts: Vec<&str> = case.Q1.x.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.Q1.y.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_q1 = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_q1, q1);

            // Check P
            let x_str_parts: Vec<&str> = case.P.x.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.P.y.split(',').collect();
            let a = Big::from_bytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::from_bytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_p = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_p, p);
        }
    }

    #[test]
    fn test_hash_to_curve_g1() {
        const H2C_SUITE_G1: &str = "BLS12381G1_XMD:SHA-256_SSWU_RO_";

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
            let p = r.mul(&Big::new_ints(&H_EFF_G1));

            // Verify against hash_to_curve()
            let hash_to_curve_p =
                hash_to_curve_g1(case.msg.as_bytes(), test_vectors.dst.as_bytes());
            assert_eq!(hash_to_curve_p, p);

            // Verify hash to curve outputs
            // Check u
            assert_eq!(case.u.len(), u.len());
            for (i, u_str) in case.u.iter().enumerate() {
                // Convert case 'u[i]' to FP
                let a = Big::from_bytes(&hex::decode(&u_str.get(2..).unwrap()).unwrap());
                let expected_u_i = FP::new_big(a);

                // Verify u[i]
                assert_eq!(expected_u_i, u[i]);
            }

            // Check Q0
            let a = Big::from_bytes(&hex::decode(&case.Q0.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::from_bytes(&hex::decode(&case.Q0.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_q0 = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_q0, q0);

            // Check Q1
            let a = Big::from_bytes(&hex::decode(&case.Q1.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::from_bytes(&hex::decode(&case.Q1.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_q1 = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_q1, q1);

            // Check P
            let a = Big::from_bytes(&hex::decode(&case.P.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::from_bytes(&hex::decode(&case.P.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_p = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_p, p);
        }
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = [0u8; 32];
        let sk = secret_key_from_bytes(&bytes);
        assert_eq!(sk, Err(AmclError::InvalidSecretKeyRange));

        let bytes = [255u8; 32];
        let sk = secret_key_from_bytes(&bytes);
        assert_eq!(sk, Err(AmclError::InvalidSecretKeyRange));

        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let sk = secret_key_from_bytes(&bytes).unwrap();
        assert!(sk.is_unity());

        let mut bytes = [255u8; 32];
        bytes[0] = 0;
        let sk = secret_key_from_bytes(&bytes).unwrap();

        let mut sk_check = Big::new_int(1);
        sk_check.shl(31 * 8);
        sk_check.dec(1);
        sk_check.norm();
        assert_eq!(sk, sk_check);
    }

    #[test]
    fn test_secret_key_generation() {
        let ikm = [1u8; 32];
        let sk = key_generate(&ikm, &[]);

        let sk_big = secret_key_from_bytes(&sk).unwrap();
        let sk_round_trip = secret_key_to_bytes(&sk_big);

        assert_eq!(sk, sk_round_trip);
    }

    #[test]
    fn test_key_pair_generation_g1() {
        let mut rng = create_rng();

        let (sk, pk) = key_pair_generate_g1(&mut rng);

        let sk_big = secret_key_from_bytes(&sk).unwrap();
        let pk_ecp = deserialize_g2(&pk).unwrap();

        let g = ECP2::generator();
        let pk_expected = pair::g2mul(&g, &sk_big);

        assert_eq!(pk_expected, pk_ecp);
    }

    #[test]
    fn test_key_pair_generation_g2() {
        let mut rng = create_rng();

        let (sk, pk) = key_pair_generate_g2(&mut rng);

        let sk_big = secret_key_from_bytes(&sk).unwrap();
        let pk_ecp = deserialize_g1(&pk).unwrap();

        let g = ECP::generator();
        let pk_expected = pair::g1mul(&g, &sk_big);

        assert_eq!(pk_expected, pk_ecp);
    }

    #[test]
    fn test_bls_verify_g1() {
        let mut rng = create_rng();
        let (sk, pk) = key_pair_generate_g1(&mut rng);

        let msg = [2u8; 32];

        let signature = core_sign_g1(&sk, &msg, TEST_DST).unwrap();

        let valid = core_verify_g1(&pk, &msg, &signature, TEST_DST);
        assert!(valid);
    }

    #[test]
    fn test_bls_verify_g2() {
        let mut rng = create_rng();
        let (sk, pk) = key_pair_generate_g2(&mut rng);

        let msg = [2u8; 32];

        let signature = core_sign_g2(&sk, &msg, TEST_DST).unwrap();

        let valid = core_verify_g2(&pk, &msg, &signature, TEST_DST);
        assert!(valid);
    }

    #[test]
    fn test_bls_aggregate_verify_g1() {
        let n = 10;
        let mut rng = create_rng();

        let mut public_keys: Vec<Vec<u8>> = vec![];
        let mut msgs: Vec<Vec<u8>> = vec![];
        let mut signatures: Vec<Vec<u8>> = vec![];

        for i in 0..n {
            // Generate keypair
            let key_pair = key_pair_generate_g1(&mut rng);
            public_keys.push(key_pair.1.to_vec());

            // Sign message
            msgs.push(vec![i as u8; 32]);
            let signature = core_sign_g1(&key_pair.0, &msgs[i], TEST_DST).unwrap();
            signatures.push(signature.to_vec());
        }

        let signatures_refs: Vec<&[u8]> = signatures.iter().map(|sig| sig.as_slice()).collect();
        let aggregate = aggregate_g1(&signatures_refs).unwrap();

        let public_keys_refs: Vec<&[u8]> = public_keys.iter().map(|pk| pk.as_slice()).collect();
        let msgs_refs: Vec<&[u8]> = msgs.iter().map(|msg| msg.as_slice()).collect();
        let valid = core_aggregate_verify_g1(&public_keys_refs, &msgs_refs, &aggregate, TEST_DST);
        assert!(valid);
    }

    #[test]
    fn test_bls_aggregate_verify_g2() {
        let n = 10;
        let mut rng = create_rng();

        let mut public_keys: Vec<Vec<u8>> = vec![];
        let mut msgs: Vec<Vec<u8>> = vec![];
        let mut signatures: Vec<Vec<u8>> = vec![];

        for i in 0..n {
            // Generate keypair
            let key_pair = key_pair_generate_g2(&mut rng);
            public_keys.push(key_pair.1.to_vec());

            // Sign message
            msgs.push(vec![i as u8; 32]);
            let signature = core_sign_g2(&key_pair.0, &msgs[i], TEST_DST).unwrap();
            signatures.push(signature.to_vec());
        }

        let signatures_refs: Vec<&[u8]> = signatures.iter().map(|sig| sig.as_slice()).collect();
        let aggregate = aggregate_g2(&signatures_refs).unwrap();

        let public_keys_refs: Vec<&[u8]> = public_keys.iter().map(|pk| pk.as_slice()).collect();
        let msgs_refs: Vec<&[u8]> = msgs.iter().map(|msg| msg.as_slice()).collect();
        let valid = core_aggregate_verify_g2(&public_keys_refs, &msgs_refs, &aggregate, TEST_DST);
        assert!(valid);
    }

    #[test]
    fn serde_g1_round_trip() {
        let mut rng = create_rng();
        let n = 5;

        for _ in 0..n {
            let (_, compressed) = key_pair_generate_g2(&mut rng);

            let decompressed = deserialize_g1(&compressed).unwrap();
            let compressed_result = serialize_g1(&decompressed).to_vec();
            assert_eq!(compressed.to_vec(), compressed_result);
        }
    }

    #[test]
    fn serde_g2_round_trip() {
        let mut rng = create_rng();
        let n = 5;

        for _ in 0..n {
            let (_, compressed) = key_pair_generate_g1(&mut rng);

            let decompressed = deserialize_g2(&compressed).unwrap();
            let compressed_result = serialize_g2(&decompressed).to_vec();
            assert_eq!(compressed.to_vec(), compressed_result);
        }
    }

    #[test]
    fn serde_g1_known_input() {
        // Input 1
        let compressed = hex::decode("b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f").unwrap();
        let decompressed = deserialize_g1(&compressed).unwrap();
        let compressed_result = serialize_g1(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 2
        let compressed = hex::decode("b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81").unwrap();
        let decompressed = deserialize_g1(&compressed).unwrap();
        let compressed_result = serialize_g1(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 3
        let compressed = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
        let decompressed = deserialize_g1(&compressed).unwrap();
        let compressed_result = serialize_g1(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);
    }

    #[test]
    fn serde_g2_known_input() {
        // Input 1
        let compressed = hex::decode("a666d31d7e6561371644eb9ca7dbcb87257d8fd84a09e38a7a491ce0bbac64a324aa26385aebc99f47432970399a2ecb0def2d4be359640e6dae6438119cbdc4f18e5e4496c68a979473a72b72d3badf98464412e9d8f8d2ea9b31953bb24899").unwrap();
        let decompressed = deserialize_g2(&compressed).unwrap();
        let compressed_result = serialize_g2(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 2
        let compressed = hex::decode("a63e88274adb7a98d112c16f7057f388786496c8f57e03ee9052b46b15eb0166645008f8cc929eb4475e386f3e6f1df81181e97fac61e371a22f34a4622f7e343ca0d99846b175a92ad1bf1df6fd4d0800e4edb7c2eb3d8437ed10cbc2d88823").unwrap();
        let decompressed = deserialize_g2(&compressed).unwrap();
        let compressed_result = serialize_g2(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 3
        let compressed = hex::decode("b090fbc9d5c6c80fec73c567202a75664cd00c2592e472a4d81d2ed4b6a166311e809ca25eb88c5d0189cbf1baa8ea7918ca20f0b66678c0230e65eb4ebb3d621940984f71eb5481453e4489dafcc7f6ee2c863b76671467002a8f2392063005").unwrap();
        let decompressed = deserialize_g2(&compressed).unwrap();
        let compressed_result = serialize_g2(&decompressed).to_vec();
        assert_eq!(compressed, compressed_result);
    }

    #[test]
    fn serde_g1_uncompressed_round_trip() {
        let mut rng = create_rng();
        let n = 5;
        let g = ECP::generator();
        let r = Big::new_ints(&CURVE_ORDER);

        for _ in 0..n {
            let num = Big::randomnum(&r, &mut rng);
            let point = pair::g1mul(&g, &num);

            let uncompressed = serialize_uncompressed_g1(&point);
            let point_round_trip = deserialize_g1(&uncompressed).unwrap();
            assert_eq!(point, point_round_trip);
        }
    }

    #[test]
    fn serde_g2_uncompressed_round_trip() {
        let mut rng = create_rng();
        let n = 5;
        let g = ECP2::generator();
        let r = Big::new_ints(&CURVE_ORDER);

        for _ in 0..n {
            let num = Big::randomnum(&r, &mut rng);
            let point = pair::g2mul(&g, &num);

            let uncompressed = serialize_uncompressed_g2(&point);
            let point_round_trip = deserialize_g2(&uncompressed).unwrap();
            assert_eq!(point, point_round_trip);
        }
    }
}
