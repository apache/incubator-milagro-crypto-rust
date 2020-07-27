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
use super::super::fp::FP;
use super::super::fp2::FP2;

use super::{
    ISO11_XDEN, ISO11_XNUM, ISO11_YDEN, ISO11_YNUM, ISO3_XDEN, ISO3_XNUM, ISO3_YDEN, ISO3_YNUM,
};

// Returns ISO-11 Constants (X-Numerator, X-Denominator, Y-Numerator, Y-Denominator)
#[inline(always)]
fn iso11_from_constants() -> ([FP; 12], [FP; 11], [FP; 16], [FP; 16]) {
    (
        [
            // X-Numerator
            FP::new_ints(&ISO11_XNUM[0]),
            FP::new_ints(&ISO11_XNUM[1]),
            FP::new_ints(&ISO11_XNUM[2]),
            FP::new_ints(&ISO11_XNUM[3]),
            FP::new_ints(&ISO11_XNUM[4]),
            FP::new_ints(&ISO11_XNUM[5]),
            FP::new_ints(&ISO11_XNUM[6]),
            FP::new_ints(&ISO11_XNUM[7]),
            FP::new_ints(&ISO11_XNUM[8]),
            FP::new_ints(&ISO11_XNUM[9]),
            FP::new_ints(&ISO11_XNUM[10]),
            FP::new_ints(&ISO11_XNUM[11]),
        ],
        [
            // X-Denominator
            FP::new_ints(&ISO11_XDEN[0]),
            FP::new_ints(&ISO11_XDEN[1]),
            FP::new_ints(&ISO11_XDEN[2]),
            FP::new_ints(&ISO11_XDEN[3]),
            FP::new_ints(&ISO11_XDEN[4]),
            FP::new_ints(&ISO11_XDEN[5]),
            FP::new_ints(&ISO11_XDEN[6]),
            FP::new_ints(&ISO11_XDEN[7]),
            FP::new_ints(&ISO11_XDEN[8]),
            FP::new_ints(&ISO11_XDEN[9]),
            FP::new_ints(&ISO11_XDEN[10]),
        ],
        [
            // Y-Numerator
            FP::new_ints(&ISO11_YNUM[0]),
            FP::new_ints(&ISO11_YNUM[1]),
            FP::new_ints(&ISO11_YNUM[2]),
            FP::new_ints(&ISO11_YNUM[3]),
            FP::new_ints(&ISO11_YNUM[4]),
            FP::new_ints(&ISO11_YNUM[5]),
            FP::new_ints(&ISO11_YNUM[6]),
            FP::new_ints(&ISO11_YNUM[7]),
            FP::new_ints(&ISO11_YNUM[8]),
            FP::new_ints(&ISO11_YNUM[9]),
            FP::new_ints(&ISO11_YNUM[10]),
            FP::new_ints(&ISO11_YNUM[11]),
            FP::new_ints(&ISO11_YNUM[12]),
            FP::new_ints(&ISO11_YNUM[13]),
            FP::new_ints(&ISO11_YNUM[14]),
            FP::new_ints(&ISO11_YNUM[15]),
        ],
        [
            // Y-Denominator
            FP::new_ints(&ISO11_YDEN[0]),
            FP::new_ints(&ISO11_YDEN[1]),
            FP::new_ints(&ISO11_YDEN[2]),
            FP::new_ints(&ISO11_YDEN[3]),
            FP::new_ints(&ISO11_YDEN[4]),
            FP::new_ints(&ISO11_YDEN[5]),
            FP::new_ints(&ISO11_YDEN[6]),
            FP::new_ints(&ISO11_YDEN[7]),
            FP::new_ints(&ISO11_YDEN[8]),
            FP::new_ints(&ISO11_YDEN[9]),
            FP::new_ints(&ISO11_YDEN[10]),
            FP::new_ints(&ISO11_YDEN[11]),
            FP::new_ints(&ISO11_YDEN[12]),
            FP::new_ints(&ISO11_YDEN[13]),
            FP::new_ints(&ISO11_YDEN[14]),
            FP::new_ints(&ISO11_YDEN[15]),
        ],
    )
}

/// Mapping from 11-Isogeny Curve to BLS12-381 ECP
///
/// Adjusted from https://eprint.iacr.org/2019/403
/// to convert projectives to (XZ, YZ, Z)
pub fn iso11_to_ecp(iso_x: &FP, iso_y: &FP) -> ECP {
    let (x_num, x_den, y_num, y_den) = iso11_from_constants();
    let polynomials_coefficients: [&[FP]; 4] = [&x_num, &x_den, &y_num, &y_den];

    // x-num, x-den, y-num, y-den
    let mut mapped_vals: [FP; 4] = [FP::new(), FP::new(), FP::new(), FP::new()];

    // Horner caculation for evaluating polynomials
    for (i, coefficients) in polynomials_coefficients[..].iter().enumerate() {
        mapped_vals[i] = coefficients[coefficients.len() - 1].clone();
        for k in coefficients.iter().rev().skip(1) {
            mapped_vals[i].mul(&iso_x);
            mapped_vals[i].add(&k);
        }
    }

    // y-num multiplied by y
    mapped_vals[2].mul(&iso_y);

    let mut z = mapped_vals[1].clone(); // x-den
    z.mul(&mapped_vals[3]); // x-den * y-den

    let mut x = mapped_vals[0].clone(); // x-num
    x.mul(&mapped_vals[3]); // x-num * y-den

    let mut y = mapped_vals[2].clone(); // y-num
    y.mul(&mapped_vals[1]); // y-num * x-den

    ECP::new_projective(x, y, z)
}

// Returns ISO-3 Constants (X-Numerator, X-Denominator, Y-Numerator, Y-Denominator)
#[inline(always)]
fn iso3_from_constants() -> ([FP2; 4], [FP2; 4], [FP2; 4], [FP2; 4]) {
    (
        [
            // X-Numerator
            FP2::new_fps(FP::new_ints(&ISO3_XNUM[0]), FP::new_ints(&ISO3_XNUM[1])),
            FP2::new_fps(FP::new_ints(&ISO3_XNUM[2]), FP::new_ints(&ISO3_XNUM[3])),
            FP2::new_fps(FP::new_ints(&ISO3_XNUM[4]), FP::new_ints(&ISO3_XNUM[5])),
            FP2::new_fps(FP::new_ints(&ISO3_XNUM[6]), FP::new_ints(&ISO3_XNUM[7])),
        ],
        [
            // X-Denominator
            FP2::new_fps(FP::new_ints(&ISO3_XDEN[0]), FP::new_ints(&ISO3_XDEN[1])),
            FP2::new_fps(FP::new_ints(&ISO3_XDEN[2]), FP::new_ints(&ISO3_XDEN[3])),
            FP2::new_fps(FP::new_ints(&ISO3_XDEN[4]), FP::new_ints(&ISO3_XDEN[5])),
            FP2::new_fps(FP::new_ints(&ISO3_XDEN[6]), FP::new_ints(&ISO3_XDEN[7])),
        ],
        [
            // Y-Numerator
            FP2::new_fps(FP::new_ints(&ISO3_YNUM[0]), FP::new_ints(&ISO3_YNUM[1])),
            FP2::new_fps(FP::new_ints(&ISO3_YNUM[2]), FP::new_ints(&ISO3_YNUM[3])),
            FP2::new_fps(FP::new_ints(&ISO3_YNUM[4]), FP::new_ints(&ISO3_YNUM[5])),
            FP2::new_fps(FP::new_ints(&ISO3_YNUM[6]), FP::new_ints(&ISO3_YNUM[7])),
        ],
        [
            // Y-Denominator
            FP2::new_fps(FP::new_ints(&ISO3_YDEN[0]), FP::new_ints(&ISO3_YDEN[1])),
            FP2::new_fps(FP::new_ints(&ISO3_YDEN[2]), FP::new_ints(&ISO3_YDEN[3])),
            FP2::new_fps(FP::new_ints(&ISO3_YDEN[4]), FP::new_ints(&ISO3_YDEN[5])),
            FP2::new_fps(FP::new_ints(&ISO3_YDEN[6]), FP::new_ints(&ISO3_YDEN[7])),
        ],
    )
}

/// Mapping from 3-Isogeny Curve to BLS12-381 ECP2
///
/// Adjusted from https://eprint.iacr.org/2019/403
/// to convert projectives to (XZ, YZ, Z)
pub fn iso3_to_ecp2(iso_x: &FP2, iso_y: &FP2) -> ECP2 {
    let (x_num, x_den, y_num, y_den) = iso3_from_constants();
    let polynomials_coefficients: [&[FP2; 4]; 4] = [&x_num, &x_den, &y_num, &y_den];

    // x-num, x-den, y-num, y-den
    let mut mapped_vals: [FP2; 4] = [FP2::new(), FP2::new(), FP2::new(), FP2::new()];

    // Horner caculation for evaluating polynomials
    for (i, coefficients) in polynomials_coefficients[..].iter().enumerate() {
        mapped_vals[i] = coefficients[coefficients.len() - 1].clone();
        for k in coefficients.iter().rev().skip(1) {
            mapped_vals[i].mul(&iso_x);
            mapped_vals[i].add(&k);
        }
    }

    // y-num multiplied by y
    mapped_vals[2].mul(&iso_y);

    let mut z = mapped_vals[1].clone(); // x-den
    z.mul(&mapped_vals[3]); // x-den * y-den

    let mut x = mapped_vals[0].clone(); // x-num
    x.mul(&mapped_vals[3]); // x-num * y-den

    let mut y = mapped_vals[2].clone(); // y-num
    y.mul(&mapped_vals[1]); // y-num * x-den

    ECP2::new_projective(x, y, z)
}
