use super::core;

use errors::AmclError;

/*************************************************************************************************
* Functions for Basic Scheme - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
*************************************************************************************************/

/// Basic Scheme - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, AmclError> {
    core::core_sign_g1(secret_key, msg)
}

/// Basic Scheme - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g1(public_key, msg, signature)
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

/// Basic Scheme - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, AmclError> {
    core::core_sign_g2(secret_key, msg)
}

/// Basic Scheme - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
pub fn verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    core::core_verify_g2(public_key, msg, signature)
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
