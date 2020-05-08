use super::super::ecp::ECP;
use super::super::ecp2::ECP2;
use super::super::pair;
use super::super::rom::{DST_G1, DST_G2, DST_POP_G1, DST_POP_G2};
use super::core;
use super::core::{
    hash_to_curve_g1, hash_to_curve_g2, secret_key_from_bytes, subgroup_check_g1,
    subgroup_check_g2, G1_BYTES, G2_BYTES, SECRET_KEY_BYTES,
};

use errors::AmclError;
use rand::RAND;

/*************************************************************************************************
* Functions for Proof of Possession - signatures on either G1 or G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
*************************************************************************************************/

/// Proof of Possession - KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    core::key_generate(ikm, key_info)
}

/*************************************************************************************************
* Functions for Proof of Possession - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub fn key_pair_generate_g1(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G2_BYTES]) {
    core::key_pair_generate_g1(rng)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.4
pub fn secret_key_to_public_key_g1(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    core::secret_key_to_public_key_g1(secret_key)
}

/// Proof of Possession - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    core::core_sign_g1(secret_key, msg)
}

/// Proof of Possession - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g1(public_key, msg, signature)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    core::aggregate_g1(points)
}

/// Proof of Possession - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn aggregate_verify_g1(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    core::core_aggregate_verify_g1(public_keys, msgs, signature)
}

/// Proof of Possession - PopProve
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.2
pub fn pop_prove_g1(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP2::generator();
    let public_key = pair::g2mul(&g, &secret_key);

    let mut public_key_bytes = [0u8; G2_BYTES];
    public_key.tobytes(&mut public_key_bytes);

    let hash = hash_to_curve_g1(&public_key_bytes, DST_POP_G1);
    let proof = pair::g1mul(&hash, &secret_key);

    let mut proof_bytes = [0u8; G1_BYTES];
    proof.tobytes(&mut proof_bytes, true);

    Ok(proof_bytes)
}

/// Proof of Possession - PopVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.3
pub fn pop_verify_g1(public_key_bytes: &[u8], proof_bytes: &[u8]) -> bool {
    // TODO: return false if bytes are invalid
    let proof = ECP::frombytes(proof_bytes);
    let public_key = ECP2::frombytes(public_key_bytes);

    if !subgroup_check_g1(&proof) || !subgroup_check_g2(&public_key) {
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
    v.isunity()
}

/// Proof of Possession - FastAggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.4
pub fn fast_aggregate_verify_g1(public_keys: &[&[u8]], msg: &[u8], signature: &[u8]) -> bool {
    if public_keys.len() == 0 {
        return false;
    }

    // TODO: return false if bytes are invalid
    let signature = ECP::frombytes(&signature);

    let hash = hash_to_curve_g1(msg, DST_G1);
    let mut g = ECP2::generator();
    g.neg();

    let mut aggregate_public_key = ECP2::frombytes(&public_keys[0]);
    for public_key in public_keys.iter().skip(1) {
        // TODO: return false if bytes are invalid
        let public_key = ECP2::frombytes(public_key);
        aggregate_public_key.add(&public_key);
    }

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &signature);
    pair::another(&mut r, &aggregate_public_key, &hash);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.isunity()
}

/*************************************************************************************************
* Functions for Proof of Possession - signatures on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub fn key_pair_generate_g2(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G1_BYTES]) {
    core::key_pair_generate_g2(rng)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.4
pub fn secret_key_to_public_key_g2(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    core::secret_key_to_public_key_g2(secret_key)
}

/// Proof of Possession - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    core::core_sign_g2(secret_key, msg)
}

/// Proof of Possession - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g2(public_key, msg, signature)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    core::aggregate_g2(points)
}

/// Proof of Possession - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
pub fn aggregate_verify_g2(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    core::core_aggregate_verify_g2(public_keys, msgs, signature)
}

/// Proof of Possession - PopProve
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.2
pub fn pop_prove_g2(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP::generator();
    let public_key = pair::g1mul(&g, &secret_key);

    let mut public_key_bytes = [0u8; G1_BYTES];
    public_key.tobytes(&mut public_key_bytes, true);

    let hash = hash_to_curve_g2(&public_key_bytes, DST_POP_G2);
    let proof = pair::g2mul(&hash, &secret_key);

    let mut proof_bytes = [0u8; G2_BYTES];
    proof.tobytes(&mut proof_bytes);

    Ok(proof_bytes)
}

/// Proof of Possession - PopVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.3
pub fn pop_verify_g2(public_key_bytes: &[u8], proof_bytes: &[u8]) -> bool {
    // TODO: return false if bytes are invalid
    let proof = ECP2::frombytes(proof_bytes);
    let public_key = ECP::frombytes(public_key_bytes);

    if !subgroup_check_g1(&public_key) || !subgroup_check_g2(&proof) {
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
    v.isunity()
}

/// Proof of Possession - FastAggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.4
pub fn fast_aggregate_verify_g2(public_keys: &[&[u8]], msg: &[u8], signature: &[u8]) -> bool {
    if public_keys.len() == 0 {
        return false;
    }

    // TODO: return false if bytes are Invalid
    let signature = ECP2::frombytes(&signature);

    let hash = hash_to_curve_g2(msg, DST_G2);
    let mut g = ECP::generator();
    g.neg();

    let mut aggregate_public_key = ECP::frombytes(&public_keys[0]);
    for public_key in public_keys.iter().skip(1) {
        // TODO: return false if bytes are Invalid
        let public_key = ECP::frombytes(public_key);
        aggregate_public_key.add(&public_key);
    }

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &signature, &g);
    pair::another(&mut r, &hash, &aggregate_public_key);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.isunity()
}
