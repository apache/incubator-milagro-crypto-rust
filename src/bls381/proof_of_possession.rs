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

use super::super::ecp::ECP;
use super::super::ecp2::ECP2;
use super::super::pair;
use super::core::{
    self, deserialize_g1, deserialize_g2, hash_to_curve_g1, hash_to_curve_g2,
    secret_key_from_bytes, serialize_g1, serialize_g2, subgroup_check_g1, subgroup_check_g2,
};
use crate::errors::AmclError;
use crate::rand::RAND;

// Re-export constants from core.
pub use super::core::{G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};

/// Domain Separation Tag for signatures on G1
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain Separation Tag for PopProve and PopVerify for signatures on G1
pub const DST_POP_G1: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain Separation Tag for signatures on G2
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain Separation Tag for PopProve and PopVerify with signatures on G2
pub const DST_POP_G2: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/*************************************************************************************************
* Functions for Proof of Possession - signatures on either G1 or G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
*************************************************************************************************/

/// Proof of Possession - KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    core::key_generate(ikm, key_info)
}

/*************************************************************************************************
* Functions for Proof of Possession - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub fn key_pair_generate_g1(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G2_BYTES]) {
    core::key_pair_generate_g1(rng)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.4
pub fn secret_key_to_public_key_g1(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    core::secret_key_to_public_key_g1(secret_key)
}

/// Proof of Possession - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    core::core_sign_g1(secret_key, msg, DST_G1)
}

/// Proof of Possession - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g1(public_key, msg, signature, DST_G1)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    core::aggregate_g1(points)
}

/// Proof of Possession - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn aggregate_verify_g1(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    core::core_aggregate_verify_g1(public_keys, msgs, signature, DST_G1)
}

/// Proof of Possession - PopProve
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.2
pub fn pop_prove_g1(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP2::generator();
    let public_key = pair::g2mul(&g, &secret_key);
    let public_key_bytes = serialize_g2(&public_key);

    let hash = hash_to_curve_g1(&public_key_bytes, DST_POP_G1);
    let proof = pair::g1mul(&hash, &secret_key);

    Ok(serialize_g1(&proof))
}

/// Proof of Possession - PopVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.3
pub fn pop_verify_g1(public_key_bytes: &[u8], proof_bytes: &[u8]) -> bool {
    let proof = deserialize_g1(proof_bytes);
    let public_key = deserialize_g2(public_key_bytes);

    if proof.is_err() || public_key.is_err() {
        return false;
    }

    let proof = proof.unwrap();
    let public_key = public_key.unwrap();

    if !subgroup_check_g1(&proof) || !subgroup_check_g2(&public_key) || public_key.is_infinity() {
        return false;
    }

    let hash = hash_to_curve_g1(&public_key_bytes, DST_POP_G1);
    let mut g = ECP2::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &proof);
    pair::another(&mut r, &public_key, &hash);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}

/// Proof of Possession - FastAggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.4
pub fn fast_aggregate_verify_g1(public_keys: &[&[u8]], msg: &[u8], signature: &[u8]) -> bool {
    if public_keys.len() == 0 {
        return false;
    }

    let signature = deserialize_g1(signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();

    let hash = hash_to_curve_g1(msg, DST_G1);
    let mut g = ECP2::generator();
    g.neg();

    let mut aggregate_public_key = ECP2::from_bytes(&public_keys[0]);
    for public_key in public_keys.iter().skip(1) {
        let public_key = deserialize_g2(public_key);
        if public_key.is_err() {
            return false;
        }
        let public_key = public_key.unwrap();

        aggregate_public_key.add(&public_key);
    }

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &signature);
    pair::another(&mut r, &aggregate_public_key, &hash);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}

/*************************************************************************************************
* Functions for Proof of Possession - signatures on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub fn key_pair_generate_g2(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G1_BYTES]) {
    core::key_pair_generate_g2(rng)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.4
pub fn secret_key_to_public_key_g2(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    core::secret_key_to_public_key_g2(secret_key)
}

/// Proof of Possession - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    core::core_sign_g2(secret_key, msg, DST_G2)
}

/// Proof of Possession - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g2(public_key, msg, signature, DST_G2)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    core::aggregate_g2(points)
}

/// Proof of Possession - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
pub fn aggregate_verify_g2(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    core::core_aggregate_verify_g2(public_keys, msgs, signature, DST_G2)
}

/// Proof of Possession - PopProve
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.2
pub fn pop_prove_g2(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP::generator();
    let public_key = pair::g1mul(&g, &secret_key);
    let public_key_bytes = serialize_g1(&public_key);

    let hash = hash_to_curve_g2(&public_key_bytes, DST_POP_G2);
    let proof = pair::g2mul(&hash, &secret_key);

    Ok(serialize_g2(&proof))
}

/// Proof of Possession - PopVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.3
pub fn pop_verify_g2(public_key_bytes: &[u8], proof_bytes: &[u8]) -> bool {
    let proof = deserialize_g2(proof_bytes);
    let public_key = deserialize_g1(public_key_bytes);

    if proof.is_err() || public_key.is_err() {
        return false;
    }

    let proof = proof.unwrap();
    let public_key = public_key.unwrap();

    if !subgroup_check_g1(&public_key) || public_key.is_infinity() || !subgroup_check_g2(&proof) {
        return false;
    }

    let hash = hash_to_curve_g2(&public_key_bytes, DST_POP_G2);
    let mut g = ECP::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &proof, &g);
    pair::another(&mut r, &hash, &public_key);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}

/// Proof of Possession - FastAggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3.4
pub fn fast_aggregate_verify_g2(public_keys: &[&[u8]], msg: &[u8], signature: &[u8]) -> bool {
    if public_keys.len() == 0 {
        return false;
    }

    let signature = deserialize_g2(&signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();

    let hash = hash_to_curve_g2(msg, DST_G2);
    let mut g = ECP::generator();
    g.neg();

    let mut aggregate_public_key = ECP::from_bytes(&public_keys[0]);
    for public_key in public_keys.iter().skip(1) {
        let public_key = deserialize_g1(public_key);
        if public_key.is_err() {
            return false;
        }
        let public_key = public_key.unwrap();

        aggregate_public_key.add(&public_key);
    }

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &signature, &g);
    pair::another(&mut r, &hash, &aggregate_public_key);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.is_unity()
}
