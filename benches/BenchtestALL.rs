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

#![allow(non_snake_case)]
extern crate amcl;

use amcl::arch;
use amcl::rand::RAND;
use amcl::types::CurvePairingType;

use std::time::Instant;

const MIN_ITERS: isize = 10;
const MIN_TIME: isize = 10;

fn bn254(mut rng: &mut RAND) {
    use amcl::bn254::big;
    use amcl::bn254::ecp;
    use amcl::bn254::ecp2;
    use amcl::bn254::fp;
    use amcl::bn254::pair;
    use amcl::bn254::rom;
    let mut fail = false;
    println!("\nTesting/Timing BN254 Pairings");

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        println!("BN Pairing-Friendly Curve");
    }
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bls {
        println!("BLS Pairing-Friendly Curve");
    }

    println!("Modulus size {:} bits", fp::MODBITS);
    println!("{:} bit build", arch::CHUNK);

    let mut G = ecp::ECP::generator();

    let mut r = big::Big::new_ints(&rom::CURVE_ORDER);
    let mut s = big::Big::randomnum(&r, &mut rng);

    let mut P = pair::g1mul(&mut G, &mut r);

    if !P.is_infinity() {
        println!("FAILURE - rP!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        P = pair::g1mul(&mut G, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G1  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut Q = ecp2::ECP2::generator();
    let mut W = pair::g2mul(&mut Q, &mut r);

    if !W.is_infinity() {
        println!("FAILURE - rQ!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        W = pair::g2mul(&mut Q, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G2  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut w = pair::ate(&mut Q, &mut P);
    w = pair::fexp(&w);

    let mut g = pair::gtpow(&mut w, &mut r);

    if !g.is_unity() {
        println!("FAILURE - g^r!=1");
        return;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair::gtpow(&mut w, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = w.compow(&s, &mut r);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow (compressed) - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        w = pair::ate(&mut Q, &mut P);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing ATE          - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair::fexp(&w);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing FEXP         - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    P = G.clone();
    Q = W.clone();

    P = pair::g1mul(&mut P, &mut s);
    g = pair::ate(&mut Q, &mut P);
    g = pair::fexp(&g);

    P = G.clone();
    Q = pair::g2mul(&mut Q, &mut s);
    w = pair::ate(&mut Q, &mut P);
    w = pair::fexp(&w);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,sP) ");
        fail = true;
    }

    Q = W.clone();
    g = pair::ate(&mut Q, &mut P);
    g = pair::fexp(&g);
    g = pair::gtpow(&mut g, &mut s);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,P)^s ");
        fail = true;
    }
    if !fail {
        println!("All tests pass");
    }
}

fn bls383(mut rng: &mut RAND) {
    use amcl::bls383::big;
    use amcl::bls383::ecp;
    use amcl::bls383::ecp2;
    use amcl::bls383::fp;
    use amcl::bls383::pair;
    use amcl::bls383::rom;
    let mut fail = false;
    println!("\nTesting/Timing BLS383 Pairings");

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        println!("BN Pairing-Friendly Curve");
    }
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bls {
        println!("BLS Pairing-Friendly Curve");
    }

    println!("Modulus size {:} bits", fp::MODBITS);
    println!("{:} bit build", arch::CHUNK);

    let mut G = ecp::ECP::generator();

    let mut r = big::Big::new_ints(&rom::CURVE_ORDER);
    let mut s = big::Big::randomnum(&r, &mut rng);

    let mut P = pair::g1mul(&mut G, &mut r);

    if !P.is_infinity() {
        println!("FAILURE - rP!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        P = pair::g1mul(&mut G, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G1  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut Q = ecp2::ECP2::generator();
    let mut W = pair::g2mul(&mut Q, &mut r);

    if !W.is_infinity() {
        println!("FAILURE - rQ!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        W = pair::g2mul(&mut Q, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G2  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut w = pair::ate(&mut Q, &mut P);
    w = pair::fexp(&w);

    let mut g = pair::gtpow(&mut w, &mut r);

    if !g.is_unity() {
        println!("FAILURE - g^r!=1");
        return;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair::gtpow(&mut w, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = w.compow(&s, &mut r);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow (compressed) - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        w = pair::ate(&mut Q, &mut P);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing ATE          - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair::fexp(&w);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing FEXP         - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    P = G.clone();
    Q = W.clone();

    P = pair::g1mul(&mut P, &mut s);
    g = pair::ate(&mut Q, &mut P);
    g = pair::fexp(&g);

    P = G.clone();
    Q = pair::g2mul(&mut Q, &mut s);
    w = pair::ate(&mut Q, &mut P);
    w = pair::fexp(&w);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,sP) ");
        fail = true;
    }

    Q = W.clone();
    g = pair::ate(&mut Q, &mut P);
    g = pair::fexp(&g);
    g = pair::gtpow(&mut g, &mut s);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,P)^s ");
        fail = true;
    }
    if !fail {
        println!("All tests pass");
    }
}

fn bls24(mut rng: &mut RAND) {
    use amcl::bls24::big;
    use amcl::bls24::ecp;
    use amcl::bls24::ecp4;
    use amcl::bls24::fp;
    use amcl::bls24::pair192;
    use amcl::bls24::rom;
    let mut fail = false;
    println!("\nTesting/Timing BLS24 Pairings");

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        println!("BN Pairing-Friendly Curve");
    }
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bls {
        println!("BLS24 Pairing-Friendly Curve");
    }

    println!("Modulus size {:} bits", fp::MODBITS);
    println!("{:} bit build", arch::CHUNK);

    let mut G = ecp::ECP::generator();

    let mut r = big::Big::new_ints(&rom::CURVE_ORDER);
    let mut s = big::Big::randomnum(&r, &mut rng);

    let mut P = pair192::g1mul(&mut G, &mut r);

    if !P.is_infinity() {
        println!("FAILURE - rP!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        P = pair192::g1mul(&mut G, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G1  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut Q = ecp4::ECP4::generator();
    let mut W = pair192::g2mul(&mut Q, &mut r);

    if !W.is_infinity() {
        println!("FAILURE - rQ!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        W = pair192::g2mul(&mut Q, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G2  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut w = pair192::ate(&mut Q, &mut P);
    w = pair192::fexp(&w);

    let mut g = pair192::gtpow(&mut w, &mut r);

    if !g.is_unity() {
        println!("FAILURE - g^r!=1");
        return;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair192::gtpow(&mut w, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = w.compow(&s, &mut r);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow (compressed) - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        w = pair192::ate(&mut Q, &mut P);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing ATE          - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair192::fexp(&w);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing FEXP         - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    P = G.clone();
    Q = W.clone();

    P = pair192::g1mul(&mut P, &mut s);
    g = pair192::ate(&mut Q, &mut P);
    g = pair192::fexp(&g);

    P = G.clone();
    Q = pair192::g2mul(&mut Q, &mut s);
    w = pair192::ate(&mut Q, &mut P);
    w = pair192::fexp(&w);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,sP) ");
        fail = true;
    }

    Q = W.clone();
    g = pair192::ate(&mut Q, &mut P);
    g = pair192::fexp(&g);
    g = pair192::gtpow(&mut g, &mut s);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,P)^s ");
        fail = true;
    }
    if !fail {
        println!("All tests pass");
    }
}

fn bls48(mut rng: &mut RAND) {
    use amcl::bls48::big;
    use amcl::bls48::ecp;
    use amcl::bls48::ecp8;
    use amcl::bls48::fp;
    use amcl::bls48::pair256;
    use amcl::bls48::rom;
    let mut fail = false;
    println!("\nTesting/Timing BLS48 Pairings");

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        println!("BN Pairing-Friendly Curve");
    }
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bls {
        println!("BLS48 Pairing-Friendly Curve");
    }

    println!("Modulus size {:} bits", fp::MODBITS);
    println!("{:} bit build", arch::CHUNK);

    let mut G = ecp::ECP::generator();

    let mut r = big::Big::new_ints(&rom::CURVE_ORDER);
    let mut s = big::Big::randomnum(&r, &mut rng);

    let mut P = pair256::g1mul(&mut G, &mut r);

    if !P.is_infinity() {
        println!("FAILURE - rP!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        P = pair256::g1mul(&mut G, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G1  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut Q = ecp8::ECP8::generator();
    let mut W = pair256::g2mul(&mut Q, &mut r);

    if !W.is_infinity() {
        println!("FAILURE - rQ!=O");
        fail = true;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        W = pair256::g2mul(&mut Q, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("G2  mul              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let mut w = pair256::ate(&mut Q, &mut P);
    w = pair256::fexp(&w);

    let mut g = pair256::gtpow(&mut w, &mut r);

    if !g.is_unity() {
        println!("FAILURE - g^r!=1");
        return;
    }

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair256::gtpow(&mut w, &mut s);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow              - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = w.compow(&s, &mut r);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("GT  pow (compressed) - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        w = pair256::ate(&mut Q, &mut P);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing ATE          - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    let start = Instant::now();
    let mut iterations = 0;
    let mut dur = 0 as u64;
    while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
        let _ = pair256::fexp(&w);
        iterations += 1;
        let elapsed = start.elapsed();
        dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
    }
    let duration = (dur as f64) / (iterations as f64);
    print!("PAIRing FEXP         - {:} iterations  ", iterations);
    println!(" {:0.2} ms per iteration", duration);

    P = G.clone();
    Q = W.clone();

    P = pair256::g1mul(&mut P, &mut s);
    g = pair256::ate(&mut Q, &mut P);
    g = pair256::fexp(&g);

    P = G.clone();
    Q = pair256::g2mul(&mut Q, &mut s);
    w = pair256::ate(&mut Q, &mut P);
    w = pair256::fexp(&w);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,sP) ");
        fail = true;
    }

    Q = W.clone();
    g = pair256::ate(&mut Q, &mut P);
    g = pair256::fexp(&g);
    g = pair256::gtpow(&mut g, &mut s);

    if !g.equals(&mut w) {
        println!("FAILURE - e(sQ,p)!=e(Q,P)^s ");
        fail = true;
    }
    if !fail {
        println!("All tests pass");
    }
}

#[allow(non_snake_case)]
fn main() {
    let mut raw: [u8; 100] = [0; 100];

    let mut rng = RAND::new();
    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }

    rng.seed(100, &raw);

    bn254(&mut rng);
    bls383(&mut rng);
    bls24(&mut rng);
    bls48(&mut rng);
}
