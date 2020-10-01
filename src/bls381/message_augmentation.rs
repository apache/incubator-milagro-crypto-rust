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

use super::core;
use crate::errors::AmclError;
use crate::rand::RAND;

// Re-export constants from core.
pub use super::core::{G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};

/// Domain Separation Tag for signatures on G1
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
/// Domain Separation Tag for signatures on G2
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";

/*************************************************************************************************
* Functions for Message Augmentation - signatures on either G1 or G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.3
*************************************************************************************************/

/// Message Augmentation - KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    core::key_generate(ikm, key_info)
}

/*************************************************************************************************
* Functions for Message Augmentation - signatures on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.2
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

/// Message Augmentation - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1
pub fn sign_g1(
    secret_key: &[u8],
    msg: &[u8],
    public_key: &[u8],
) -> Result<[u8; G1_BYTES], AmclError> {
    // Message = (public_key || msg)
    let mut augmented_msg = public_key.to_vec();
    augmented_msg.extend_from_slice(msg);

    core::core_sign_g1(secret_key, &augmented_msg, DST_G1)
}

/// Message Augmentation - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1
pub fn verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    // Message = (public_key || msg)
    let mut augmented_msg = public_key.to_vec();
    augmented_msg.extend_from_slice(msg);

    core::core_verify_g1(&public_key, &augmented_msg, &signature, DST_G1)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    core::aggregate_g1(points)
}

/// Message Augmentation - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1.1
pub fn aggregate_verify_g1(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    // Augment each message
    let mut augmented_msgs: Vec<Vec<u8>> = Vec::with_capacity(msgs.len());
    for (i, msg) in msgs.iter().enumerate() {
        // Message = (public_key || msg)
        let mut public_key_msg = public_keys[i].to_vec();
        public_key_msg.extend_from_slice(msg);

        augmented_msgs.push(public_key_msg);
    }

    let msgs_refs: Vec<&[u8]> = augmented_msgs
        .iter()
        .map(|bytes| bytes.as_slice())
        .collect();
    core::core_aggregate_verify_g1(public_keys, &msgs_refs, signature, DST_G1)
}

/*************************************************************************************************
* Functions for Message Augmentation - signatures on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.2
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

/// Message Augmentation - Sign
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1
pub fn sign_g2(
    secret_key: &[u8],
    msg: &[u8],
    public_key: &[u8],
) -> Result<[u8; G2_BYTES], AmclError> {
    // Message = (public_key || msg)
    let mut augmented_msg = public_key.to_vec();
    augmented_msg.extend_from_slice(msg);

    core::core_sign_g2(secret_key, &augmented_msg, DST_G2)
}

/// Message Augmentation - Verify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1
pub fn verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    // Message = (public_key || msg)
    let mut augmented_msg = public_key.to_vec();
    augmented_msg.extend_from_slice(msg);

    core::core_verify_g2(public_key, &augmented_msg, signature, DST_G2)
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
pub fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    core::aggregate_g2(points)
}

/// Message Augmentation - AggregateVerify
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-3.1.1
pub fn aggregate_verify_g2(public_keys: &[&[u8]], msgs: &[&[u8]], signature: &[u8]) -> bool {
    // Augment each message
    let mut augmented_msgs: Vec<Vec<u8>> = Vec::with_capacity(msgs.len());
    for (i, msg) in msgs.iter().enumerate() {
        // Message = (public_key || msg)
        let mut public_key_msg = public_keys[i].to_vec();
        public_key_msg.extend_from_slice(msg);

        augmented_msgs.push(public_key_msg);
    }

    let msgs_refs: Vec<&[u8]> = augmented_msgs
        .iter()
        .map(|bytes| bytes.as_slice())
        .collect();
    core::core_aggregate_verify_g2(public_keys, &msgs_refs, signature, DST_G2)
}
