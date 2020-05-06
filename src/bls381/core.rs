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
pub(crate) fn key_generate(ikm: &[u8], key_info: &[u8]) -> Vec<u8> {
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
    let mut secret_key_bytes = vec![0u8; MODBYTES - secret_key.len()];
    secret_key_bytes.extend_from_slice(secret_key);

    // Ensure secret key is in the range [0, r-1].
    let secret_key = Big::frombytes(&secret_key_bytes);
    if secret_key >= Big::new_ints(&CURVE_ORDER) {
        return Err(AmclError::InvalidSecretKeyRange);
    }

    Ok(secret_key)
}

// Converts secret key Big to bytes
pub(crate) fn secret_key_to_bytes(secret_key: &Big) -> Vec<u8> {
    let mut secret_key_bytes = vec![0u8; MODBYTES];
    secret_key.tobytes(&mut secret_key_bytes);
    secret_key_bytes[MODBYTES - SECRET_KEY_BYTES..].to_vec();
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
pub(crate) fn key_pair_generate_g1(rng: &mut RAND) -> (Vec<u8>, Vec<u8>) {
    // Fill random bytes
    let mut ikm: Vec<u8> = Vec::with_capacity(SECRET_KEY_BYTES);
    for _ in 0..SECRET_KEY_BYTES {
        ikm.push(rng.getbyte());
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
pub(crate) fn secret_key_to_public_key_g1(secret_key: &[u8]) -> Result<Vec<u8>, AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP2::generator();
    let public_key = pair::g2mul(&g, &secret_key);

    // Convert to bytes
    let mut public_key_bytes = vec![0u8; G2_BYTES];
    public_key.tobytes(&mut public_key_bytes);
    Ok(public_key_bytes)
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let hash = hash_to_curve_g1(msg, DST_G1);
    let signature = pair::g1mul(&hash, &secret_key);

    let mut signed_message_bytes = vec![0u8; G1_BYTES];
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
pub(crate) fn aggregate_g1(points: &[&[u8]]) -> Result<Vec<u8>, AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    // TODO: Error rather than panic if bytes are invalid
    let mut aggregate = ECP::frombytes(&points[0]);
    for point in points.iter().skip(1) {
        aggregate.add(&ECP::frombytes(&point));
    }

    // Return compressed point
    let mut aggregate_bytes = vec![0u8; G1_BYTES];
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
pub(crate) fn key_pair_generate_g2(rng: &mut RAND) -> (Vec<u8>, Vec<u8>) {
    // Fill random bytes
    let mut ikm: Vec<u8> = Vec::with_capacity(SECRET_KEY_BYTES);
    for _ in 0..SECRET_KEY_BYTES {
        ikm.push(rng.getbyte());
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
pub(crate) fn secret_key_to_public_key_g2(secret_key: &[u8]) -> Result<Vec<u8>, AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP::generator();
    let public_key = pair::g1mul(&g, &secret_key);

    // Convert to bytes
    let mut public_key_bytes = vec![0u8; G1_BYTES];
    public_key.tobytes(&mut public_key_bytes, true);
    Ok(public_key_bytes)
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;

    let hash = hash_to_curve_g2(msg, DST_G2);
    let signature = pair::g2mul(&hash, &secret_key);

    let mut signed_message_bytes = vec![0u8; G2_BYTES];
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
pub(crate) fn aggregate_g2(points: &[&[u8]]) -> Result<Vec<u8>, AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    // TODO: Error if bytes are invalid
    let mut aggregate = ECP2::frombytes(&points[0]);
    for point in points.iter().skip(1) {
        aggregate.add(&ECP2::frombytes(&point));
    }

    // Return uncompressed point
    let mut aggregate_bytes = vec![0u8; G2_BYTES];
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
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-6.6.2
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
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-6.6.2
fn map_to_curve_g2(u: FP2) -> ECP2 {
    let (x, y) = simplified_swu_fp2(u);
    iso3_to_ecp2(&x, &y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // The following tests were exported from
    // https://github.com/kwantam/bls_sigs_ref/tree/master/python-impl
    // Format: [(input, output)]
    // input: [u0_a, u0_b, u1_a, u1_b]
    // output: [x_a, x_b, y_a, y_b]
    pub const TESTS: [([&str; 4], [&str; 4]); 4] =
        [
            // Test 0
            (
                // Input
                [
                    "004ad233c619209060e40059b81e4c1f92796b05aa1bc6358d65e53dc0d657dfbc713d4030b0b6d9234a6634fd1944e7",
                    "0e2386c82713441bc3b06a460bd81850f4bf376ea89c80b18c0881e855c58dc8e83b2fd23af983f4786508e30c42af01",
                    "08a6a75e0a8d32f1e096f29047ea879dd34a5504218d7ce92c32c244786822fb73fbf708d167ad86537468249ec6df48",
                    "07016d0e5e13cd65780042c6f7b4c74ae1c58da438c99582696818b5c229895b893318dcb87d2a65e557d4ebeb408b70"
                ],
                // Output
                [
                    "04861c41efcc5fc56e62273692b48da25d950d2a0aaffb34eff80e8dbdc2d41ca38555ceb8554368436aea47d16056b5",
                    "09db5217528c55d982cf05fc54242bdcd25f1ebb73372e00e16d8e0f19dc3aeabdeef2d42d693405a04c37d60961526a",
                    "177d05b95e7879a7ddbd83c15114b5a4e9846fde72b2263072dc9e60db548ccbadaacb92cc4952d4f47425fe3c5e0172",
                    "0fc82c99b928ed9df12a74f9215c3df8ae1e9a3fa54c00897889296890b23a0edcbb9653f9170bf715f882b35c0b4647"
                ]
            ),
            // Test 1
            (
                // Input
                [
                    "083c57b3ee2ecba5bbf874bb03897827f949096efceea00f002c979de7e5e9429fcf1f3323d4c8c548cd6f8ecb1a5c1d",
                    "0344fdfe8e1401867a275b3bef7e6ec52450968ab8a1293938fe3d5712dda67c85afeb91d85ab83fcdbebba4dc913e44",
                    "1361b5ee134c6bee4e287e63f852b6e48546dcf0684af7cf3e7653a3427a609f769ce4d9d99a638b6ae432130fa43104",
                    "18425b12c2ab5de136eb493b88ca950a45cab942505b5dd59a8b3ae8ec34c40ada65ff2719b1fcda9769fb22882002f9"
                ],
                // Output
                [
                    "15f7a5c1168ad5ab67ff285c80fa8dd932ca88d9f8b3803c6c7b1f525d2dd5d01f2418259ae167c17c514d55e4707ddb",
                    "04378269c7364a6cefcdafdb87b004d3ebf6853f46687e46f29f23196d47a176c6f858be34c9f9a3608c74e804f6c686",
                    "023d9d46abe82bc0ac7c104d9519c037ff72893b8371d72ab92378f60a2361d7171df6b33500828c88923ddb1aab7fa5",
                    "1015adfeece3613836bf82541ea560c701e197b3d081e2c242b217d809f4ac0ca787b402537a66c0d1f6b76e1b19e94b"
                ]
            ),
            // Test 2
            (
                // Input
                [
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ],
                // Output
                [
                    "19da1b4d47efeeb154f8968b43da2125376e0999ba722141419b03fd857490562fa42a5d0973956d1932dd20c1e0a284",
                    "18426da25dadd359adfda64fbaddac4414da2a841cb467935289877db450fac424361efb2e7fb141b7b98e6b2f888aef",
                    "0c2f8d431770d9be9b087c36fc5b66bb83ce6372669f48294193ef646105e0f21d17b134e7d1ad9c18f54b81f6a3707b",
                    "03257c3be77016e69b75905a97871008a6dfd2e324a6748c48d3304380156987bd0905991824936fcfe34ab25c3b6caa"
                ]
            ),
            // Test 3
            (
                // Input
                [
                    "05495a3dfa360cb809c1904530db1986aea4bf356e634b40b51e0ee5fcb6cb75085a72a0626873a426470067627c6418",
                    "11e63b587bedb59c2140518565950bdf881d75c0cccdcedcd9f4b71f2cfede3e5fdbe0261b015562d5edeaa11b7b2b76",
                    "116c87bbeece66871eb6c2a51bc4327b10ffe470b49c28ef8eef624da766caa2cc9ff6c7042b26b2efd3404f5a81a140",
                    "010450a90c17ba2997b645ef340fb5b207d6c915b34a93d93e75ee905d6d203d4aac046e10bd4d94a215604ade7afa8e"
                ],
                // Output
                [
                    "0f1614a6e91c3e00799098fded2f2cfd72cb585cbdaec41b478509913c6772266a764f00b24a7f99607948a4b69b4d8f",
                    "13ca2148705ca7ba49c92ab8985d7babcc8afc6bf8e397fb829f5fe3f49e51c41332ba4389f5ba66667310b22bea16c9",
                    "026a743ee00eec8c7ef63351f4a3b26b2f029c10130385efc56ce53d0788db32ff5296ab77f9c389bd196cce8fc1e888",
                    "0d458d80897e922f3e7e15cfa66a0d3645d95788bddb7478af3f1b5ca662c348b0e9ffdb88fabfdb74f103fea0c2d793"
                ]
            )
        ];

    #[test]
    fn test_map_to_curve_g2() {
        for test in &TESTS {
            // Input u0 and u1
            let a = Big::frombytes(&hex::decode(test.0[0]).unwrap());
            let b = Big::frombytes(&hex::decode(test.0[1]).unwrap());
            let u0 = FP2::new_bigs(a, b);
            let a = Big::frombytes(&hex::decode(test.0[2]).unwrap());
            let b = Big::frombytes(&hex::decode(test.0[3]).unwrap());
            let u1 = FP2::new_bigs(a, b);

            // Map to Curve
            let (iso3_0_x, iso3_0_y) = simplified_swu_fp2(u0);
            let (iso3_1_x, iso3_1_y) = simplified_swu_fp2(u1);

            // 3-Isogeny Map
            let mut q0 = iso3_to_ecp2(&iso3_0_x, &iso3_0_y);
            let q1 = iso3_to_ecp2(&iso3_1_x, &iso3_1_y);
            q0.add(&q1);

            // Clear Cofactor
            q0.clear_cofactor();

            // Check expected values
            let a = Big::frombytes(&hex::decode(test.1[0]).unwrap());
            let b = Big::frombytes(&hex::decode(test.1[1]).unwrap());
            let check_x = FP2::new_bigs(a, b);
            let a = Big::frombytes(&hex::decode(test.1[2]).unwrap());
            let b = Big::frombytes(&hex::decode(test.1[3]).unwrap());
            let check_y = FP2::new_bigs(a, b);
            let check_e = ECP2::new_fp2s(check_x, check_y);

            assert!(q0.equals(&check_e));
        }
    }

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
