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

use super::big::Big;
use super::dbig::DBig;
use super::fp::FP;
use super::fp2::FP2;
use super::rom::{
    H2C_L, HASH_ALGORITHM, MODULUS, SSWU_A1, SSWU_A2_A, SSWU_A2_B, SSWU_B1, SSWU_B2_A, SSWU_B2_B,
    SSWU_Z1, SSWU_Z2_A, SSWU_Z2_B,
};
use crate::errors::AmclError;
use crate::hash256::{BLOCK_SIZE as SHA256_BLOCK_SIZE, HASH256, HASH_BYTES as SHA256_HASH_BYTES};
use crate::hash384::{BLOCK_SIZE as SHA384_BLOCK_SIZE, HASH384, HASH_BYTES as SHA384_HASH_BYTES};
use crate::hash512::{BLOCK_SIZE as SHA512_BLOCK_SIZE, HASH512, HASH_BYTES as SHA512_HASH_BYTES};

/// Oversized DST padding
pub const OVERSIZED_DST: &[u8] = b"H2C-OVERSIZE-DST-";

#[derive(Copy, Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn length(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => SHA256_HASH_BYTES,
            HashAlgorithm::Sha384 => SHA384_HASH_BYTES,
            HashAlgorithm::Sha512 => SHA512_HASH_BYTES,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => SHA256_BLOCK_SIZE,
            HashAlgorithm::Sha384 => SHA384_BLOCK_SIZE,
            HashAlgorithm::Sha512 => SHA512_BLOCK_SIZE,
        }
    }
}

/// Hash a message
pub fn hash(msg: &[u8], hash_function: HashAlgorithm) -> Vec<u8> {
    match hash_function {
        HashAlgorithm::Sha256 => {
            let mut hash = HASH256::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hash = HASH384::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hash = HASH512::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
    }
}

// Hash To Field - Fp
//
// Take a message as bytes and convert it to a Field Point
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-5.3
pub fn hash_to_field_fp(msg: &[u8], count: usize, dst: &[u8]) -> Result<Vec<FP>, AmclError> {
    let m = 1;
    let p = Big::new_ints(&MODULUS);

    let len_in_bytes = count * m * H2C_L;
    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes, dst)?;

    let mut u: Vec<FP> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let elm_offset = H2C_L as usize * i * m as usize;
        let mut dbig =
            DBig::from_bytes(&pseudo_random_bytes[elm_offset..elm_offset + H2C_L as usize]);
        let e: Big = dbig.dmod(&p);
        u.push(FP::new_big(e));
    }
    Ok(u)
}

// Hash To Field - Fp2
//
// Take a message as bytes and convert it to a vector of Field Points with extension degree 2.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-5.3
pub fn hash_to_field_fp2(msg: &[u8], count: usize, dst: &[u8]) -> Result<Vec<FP2>, AmclError> {
    let m = 2;
    let p = Big::new_ints(&MODULUS);

    let len_in_bytes = count * m * H2C_L;

    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes, dst)?;

    let mut u: Vec<FP2> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut e: Vec<Big> = Vec::with_capacity(m as usize);
        for j in 0..m as usize {
            let elm_offset = H2C_L as usize * (j + i * m as usize);
            let mut big =
                DBig::from_bytes(&pseudo_random_bytes[elm_offset..elm_offset + H2C_L as usize]);
            e.push(big.dmod(&p));
        }
        u.push(FP2::new_bigs(e[0].clone(), e[1].clone()));
    }
    Ok(u)
}

// Expand Message XMD
//
// Take a message and convert it to pseudo random bytes of specified length
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-5.4
fn expand_message_xmd(msg: &[u8], len_in_bytes: usize, dst: &[u8]) -> Result<Vec<u8>, AmclError> {
    // ell = ceiling(len_in_bytes / b_in_bytes)
    let ell = (len_in_bytes + HASH_ALGORITHM.length() - 1) / HASH_ALGORITHM.length();

    // Error if length of output less than 255 bytes
    if ell > 255 {
        return Err(AmclError::HashToFieldError);
    }

    // Create DST prime as (dst.len() || dst)
    let dst_prime = if dst.len() > 255 {
        // DST too long, shorten to H("H2C-OVERSIZE-DST-" || dst)
        let mut tmp = OVERSIZED_DST.to_vec();
        tmp.extend_from_slice(dst);
        let mut tmp = hash(&tmp, HASH_ALGORITHM).to_vec();
        tmp.push(HASH_ALGORITHM.length() as u8);
        tmp
    } else {
        // DST correct size, append length as a single byte
        let mut prime = dst.to_vec();
        prime.push(dst.len() as u8);
        prime
    };

    let mut pseudo_random_bytes: Vec<u8> = vec![];
    let mut b: Vec<Vec<u8>> = vec![vec![]; 2];

    // Set b[0] to H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let mut tmp = vec![0; HASH_ALGORITHM.block_size()];
    tmp.extend_from_slice(msg);
    let l_i_b_str: [u8; 2] = (len_in_bytes as u16).to_be_bytes();
    tmp.extend_from_slice(&l_i_b_str);
    tmp.push(0u8);
    tmp.extend_from_slice(&dst_prime);
    b[0] = hash(&tmp, HASH_ALGORITHM);

    // Set b[1] to H(b_0 || I2OSP(1, 1) || DST_prime)
    tmp = b[0].clone();
    tmp.push(1u8);
    tmp.extend_from_slice(&dst_prime);
    b[1] = hash(&tmp, HASH_ALGORITHM);

    pseudo_random_bytes.extend_from_slice(&b[1]);

    for i in 2..=ell {
        // Set b[i] to H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        tmp = b[0]
            .iter()
            .enumerate()
            .map(|(j, b_0)| {
                // Perform strxor(b[0], b[i-1])
                b_0 ^ b[i - 1][j] // b[i].len() will all be 32 bytes as they are SHA256 output.
            })
            .collect();
        tmp.push(i as u8); // i < 256
        tmp.extend_from_slice(&dst_prime);
        b.push(hash(&tmp, HASH_ALGORITHM));

        pseudo_random_bytes.extend_from_slice(&b[i]);
    }

    // Take required length
    Ok(pseudo_random_bytes[..len_in_bytes as usize].to_vec())
}

// Simplified Shallue-van de Woestijne-Ulas Method - Fp
//
// Returns projectives as (XZ, YZ, Z)
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-6.6.2
pub fn simplified_swu_fp(u: FP) -> (FP, FP) {
    let sswu_a = FP::new_big(Big::new_ints(&SSWU_A1));
    let sswu_b = FP::new_big(Big::new_ints(&SSWU_B1));
    let sswu_z = FP::new_big(Big::new_ints(&SSWU_Z1));

    // tmp1 = Z * u^2
    // tv1 = 1 / (Z^2 * u^4 + Z * u^2)
    let mut tmp1 = u.clone();
    tmp1.sqr();
    tmp1.mul(&sswu_z);
    let mut tv1 = tmp1.clone();
    tv1.sqr();
    tv1.add(&tmp1);
    tv1.inverse();

    // x = (-B / A) * (1 + tv1)
    let mut x = tv1.clone();
    x.add(&FP::new_int(1));
    x.mul(&sswu_b); // b * (Z^2 * u^4 + Z * u^2 + 1)
    x.neg();
    let mut a_inverse = sswu_a.clone();
    a_inverse.inverse();
    x.mul(&a_inverse);

    // Deal with case where Z^2 * u^4 + Z * u^2 == 0
    if tv1.is_zilch() {
        // x = B / (Z * A)
        x = sswu_z.clone();
        x.inverse();
        x.mul(&sswu_b);
        x.mul(&a_inverse);
    }

    // gx = x^3 + A * x + B
    let mut gx = x.clone();
    gx.sqr();
    gx.add(&sswu_a);
    gx.mul(&x);
    gx.add(&sswu_b);

    // y = sqrt(gx)
    let mut y = gx.clone();
    let mut y = y.sqrt();

    // Check y is valid square root
    let mut y2 = y.clone();
    y2.sqr();
    if !gx.equals(&y2) {
        // x = x * Z^2 * u
        x.mul(&tmp1);

        // gx = x^3 + A * x + B
        let mut gx = x.clone();
        gx.sqr();
        gx.add(&sswu_a);
        gx.mul(&x);
        gx.add(&sswu_b);

        y = gx.sqrt();
        y2 = y.clone();
        y2.sqr();
        assert_eq!(gx, y2, "Hash to Curve SSWU failure - no square roots");
    }

    // Negate y if y and t are opposite in sign
    if u.sgn0() != y.sgn0() {
        y.neg();
    }

    (x, y)
}

// Simplified Shallue-van de Woestijne-Ulas Method - Fp2
//
// Returns projectives as (X, Y)
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-6.6.2
pub fn simplified_swu_fp2(u: FP2) -> (FP2, FP2) {
    let sswu_a = FP2::new_bigs(Big::new_ints(&SSWU_A2_A), Big::new_ints(&SSWU_A2_B));
    let sswu_b = FP2::new_bigs(Big::new_ints(&SSWU_B2_A), Big::new_ints(&SSWU_B2_B));
    let sswu_z = FP2::new_bigs(Big::new_ints(&SSWU_Z2_A), Big::new_ints(&SSWU_Z2_B));

    // tmp1 = Z * u^2
    // tv1 = 1 / (Z^2 * u^4 + Z * u^2)
    let mut tmp1 = u.clone();
    tmp1.sqr();
    tmp1.mul(&sswu_z);
    let mut tv1 = tmp1.clone();
    tv1.sqr();
    tv1.add(&tmp1);
    tv1.inverse();

    // x = (-B / A) * (1 + tv1)
    let mut x = tv1.clone();
    x.add(&FP2::new_ints(1, 0));
    x.mul(&sswu_b); // b * (Z^2 * u^4 + Z * u^2 + 1)
    x.neg();
    let mut a_inverse = sswu_a.clone();
    a_inverse.inverse();
    x.mul(&a_inverse);

    // Deal with case where Z^2 * u^4 + Z * u^2 == 0
    if tv1.is_zilch() {
        // x = B / (Z * A)
        x = sswu_z.clone();
        x.inverse();
        x.mul(&sswu_b);
        x.mul(&a_inverse);
    }

    // gx = x^3 + A * x + B
    let mut gx = x.clone();
    gx.sqr();
    gx.add(&sswu_a);
    gx.mul(&x);
    gx.add(&sswu_b);

    // y = sqrt(gx)
    let mut y = gx.clone();
    if !y.sqrt() {
        // x = x * Z * u^2
        x.mul(&tmp1);

        // gx = x^3 + A * x + B
        let mut gx = x.clone();
        gx.sqr();
        gx.add(&sswu_a);
        gx.mul(&x);
        gx.add(&sswu_b);

        y = gx;
        assert!(y.sqrt(), "Hash to Curve SSWU failure - no square roots");
    }

    // Negate y if y and t are opposite in sign
    if u.sgn0() != y.sgn0() {
        y.neg();
    }

    (x, y)
}
