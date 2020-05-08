use super::core;
use super::core::{G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};

use errors::AmclError;
use rand::RAND;

/*************************************************************************************************
* Functions for Basic Scheme - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
*************************************************************************************************/

/// Message Augmentation - KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    core::key_generate(ikm, key_info)
}

/*************************************************************************************************
* Functions for Message Augmentation - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2
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

/// Basic Scheme - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    core::core_sign_g1(secret_key, msg)
}

/// Basic Scheme - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g1(public_key, msg, signature)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    core::aggregate_g1(points)
}

/// Basic Scheme - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1.1
pub fn aggregate_verify_g1(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    // Verify messages are unique
    for (i, msg1) in msgs.iter().enumerate() {
        for (j, msg2) in msgs.iter().enumerate() {
            if i != j && msg1 == msg2 {
                return false;
            }
        }
    }

    core::core_aggregate_verify_g1(public_keys, msgs, signature)
}

/*************************************************************************************************
* Functions for Basic Scheme - signatures on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
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

/// Basic Scheme - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    core::core_sign_g2(secret_key, msg)
}

/// Basic Scheme - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g2(public_key, msg, signature)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    core::aggregate_g2(points)
}

/// Basic Scheme - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1.1
pub fn aggregate_verify_g2(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    // Verify messages are unique
    for (i, msg1) in msgs.iter().enumerate() {
        for (j, msg2) in msgs.iter().enumerate() {
            if i == j {
                continue;
            }
            if msg1 == msg2 {
                return false;
            }
        }
    }

    core::core_aggregate_verify_g2(public_keys, msgs, signature)
}
