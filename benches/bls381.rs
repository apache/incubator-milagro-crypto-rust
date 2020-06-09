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

use amcl::bls381::bls381::basic;
use amcl::bls381::bls381::utils::*;
use amcl::bls381::*;
use amcl::rand::RAND;
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};

fn create_rng() -> RAND {
    let mut raw: [u8; 100] = [0; 100];

    let mut rng = RAND::new();
    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }

    rng.seed(100, &raw);
    rng
}

fn serialisation_g1(c: &mut Criterion) {
    let uncompressed_g1 = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
    let point = deserialize_g1(&uncompressed_g1).unwrap();
    let point_2 = point.clone();
    let compressed_g1 = serialize_g1(&point);

    c.bench(
        "serialisation",
        Benchmark::new("Deserialise Compressed G1", move |b| {
            b.iter(|| {
                black_box(deserialize_g1(&compressed_g1).unwrap());
            })
        })
        .sample_size(10),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Serialise Compress G1", move |b| {
            b.iter(|| {
                black_box(serialize_g1(&point.clone()));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Deserialise Uncompressed G1", move |b| {
            b.iter(|| {
                black_box(deserialize_g1(&uncompressed_g1).unwrap());
            })
        })
        .sample_size(10),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Serialise Uncompressed G1", move |b| {
            b.iter(|| {
                black_box(serialize_uncompressed_g1(&point_2));
            })
        })
        .sample_size(10),
    );
}

fn serialisation_g2(c: &mut Criterion) {
    let uncompressed_g2 = hex::decode("a666d31d7e6561371644eb9ca7dbcb87257d8fd84a09e38a7a491ce0bbac64a324aa26385aebc99f47432970399a2ecb0def2d4be359640e6dae6438119cbdc4f18e5e4496c68a979473a72b72d3badf98464412e9d8f8d2ea9b31953bb24899").unwrap();
    let point = deserialize_g2(&uncompressed_g2).unwrap();
    let point_2 = point.clone();
    let compressed_g2 = serialize_g2(&point);

    c.bench(
        "serialisation",
        Benchmark::new("Deserialise Compressed G2", move |b| {
            b.iter(|| {
                black_box(deserialize_g2(&compressed_g2).unwrap());
            })
        })
        .sample_size(100),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Serialise Compress G2", move |b| {
            b.iter(|| {
                black_box(serialize_g2(&point.clone()));
            })
        })
        .sample_size(20),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Deserialise Uncompressed G2", move |b| {
            b.iter(|| {
                black_box(deserialize_g2(&uncompressed_g2).unwrap());
            })
        })
        .sample_size(100),
    );

    c.bench(
        "serialisation",
        Benchmark::new("Serialise Uncompressed G2", move |b| {
            b.iter(|| {
                black_box(serialize_uncompressed_g2(&point_2));
            })
        })
        .sample_size(20),
    );
}

fn basic_signing(c: &mut Criterion) {
    // G1
    let (sk, pk) = basic::key_pair_generate_g1(&mut create_rng());

    let msg = [7u8; 32];
    let sig = basic::sign_g1(&sk, &msg).unwrap();

    c.bench(
        "basic",
        Benchmark::new("Create a Signature G1", move |b| {
            b.iter(|| {
                black_box(basic::sign_g1(&sk, &msg).unwrap());
            })
        })
        .sample_size(20),
    );

    c.bench(
        "basic",
        Benchmark::new("Verify a Signature G1", move |b| {
            b.iter(|| {
                black_box(basic::verify_g1(&pk, &msg, &sig));
            })
        })
        .sample_size(20),
    );

    // G2

    let (sk, pk) = basic::key_pair_generate_g2(&mut create_rng());

    let msg = [7u8; 32];
    let sig = basic::sign_g2(&sk, &msg).unwrap();

    c.bench(
        "basic",
        Benchmark::new("Create a Signature G2", move |b| {
            b.iter(|| {
                black_box(basic::sign_g2(&sk, &msg).unwrap());
            })
        })
        .sample_size(20),
    );

    c.bench(
        "basic",
        Benchmark::new("Verify a Signature G2", move |b| {
            b.iter(|| {
                black_box(basic::verify_g2(&pk, &msg, &sig));
            })
        })
        .sample_size(20),
    );
}

fn aggregation(c: &mut Criterion) {
    let mut rng = create_rng();
    let mut points_g1 = Vec::with_capacity(100);
    let mut points_g2 = Vec::with_capacity(100);
    for _ in 0..100 {
        let (_, g1) = basic::key_pair_generate_g2(&mut rng); // generates pk on G1
        let (_, g2) = basic::key_pair_generate_g1(&mut rng); // generates pk on G2
        points_g1.push(g1.to_vec());
        points_g2.push(g2.to_vec());
    }

    c.bench(
        "basic",
        Benchmark::new("Aggregate 100 G1 points", move |b| {
            b.iter(|| {
                let points_g1_refs: Vec<&[u8]> = points_g1.iter().map(|x| x.as_slice()).collect();
                black_box(basic::aggregate_g1(&points_g1_refs).unwrap());
            })
        })
        .sample_size(50),
    );

    c.bench(
        "basic",
        Benchmark::new("Aggregate 100 G2 points", move |b| {
            b.iter(|| {
                let points_g2_refs: Vec<&[u8]> = points_g2.iter().map(|x| x.as_slice()).collect();
                black_box(basic::aggregate_g2(&points_g2_refs).unwrap());
            })
        })
        .sample_size(50),
    );
}

fn aggregate_verfication(c: &mut Criterion) {
    let mut rng = create_rng();
    let mut pks_g1 = Vec::with_capacity(100);
    let mut pks_g2 = Vec::with_capacity(100);
    let mut sks_g1 = Vec::with_capacity(100);
    let mut sks_g2 = Vec::with_capacity(100);
    let mut msgs = Vec::with_capacity(100);
    let mut sigs_g1 = Vec::with_capacity(100);
    let mut sigs_g2 = Vec::with_capacity(100);

    for i in 0..100 {
        // Generate Keys
        let (sk_g1, pk_g1) = basic::key_pair_generate_g1(&mut rng);
        let (sk_g2, pk_g2) = basic::key_pair_generate_g2(&mut rng);
        pks_g1.push(pk_g1.to_vec());
        pks_g2.push(pk_g2.to_vec());
        sks_g1.push(sk_g1.to_vec());
        sks_g2.push(sk_g2.to_vec());

        // Sign the messages
        let msg = vec![i as u8; 32];
        let sig_g1 = basic::sign_g1(&sk_g1, &msg).unwrap();
        let sig_g2 = basic::sign_g2(&sk_g2, &msg).unwrap();
        msgs.push(msg);
        sigs_g1.push(sig_g1.to_vec());
        sigs_g2.push(sig_g2.to_vec());
    }
    let msgs_2 = msgs.clone();

    // Aggregate Signatures
    let sigs_g1_refs: Vec<&[u8]> = sigs_g1.iter().map(|x| x.as_slice()).collect();
    let sigs_g2_refs: Vec<&[u8]> = sigs_g2.iter().map(|x| x.as_slice()).collect();
    let agg_sig_g1 = basic::aggregate_g1(&sigs_g1_refs).unwrap();
    let agg_sig_g2 = basic::aggregate_g2(&sigs_g2_refs).unwrap();

    c.bench(
        "aggregation",
        Benchmark::new("Verifying aggregate of 100 signatures G1", move |b| {
            b.iter(|| {
                let pks_g1_refs: Vec<&[u8]> = pks_g1.iter().map(|x| x.as_slice()).collect();
                let msgs_refs: Vec<&[u8]> = msgs.iter().map(|x| x.as_slice()).collect();

                assert!(basic::aggregate_verify_g1(
                    &pks_g1_refs,
                    &msgs_refs,
                    &agg_sig_g1
                ));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "aggregation",
        Benchmark::new("Verifying aggregate of 100 signatures G2", move |b| {
            b.iter(|| {
                let pks_g2_refs: Vec<&[u8]> = pks_g2.iter().map(|x| x.as_slice()).collect();
                let msgs_refs: Vec<&[u8]> = msgs_2.iter().map(|x| x.as_slice()).collect();

                assert!(basic::aggregate_verify_g2(
                    &pks_g2_refs,
                    &msgs_refs,
                    &agg_sig_g2
                ));
            })
        })
        .sample_size(10),
    );
}

fn key_generation(c: &mut Criterion) {
    let mut rng = create_rng();
    c.bench(
        "key generation",
        Benchmark::new("Generate random keypair G1", move |b| {
            b.iter(|| {
                black_box(basic::key_pair_generate_g1(&mut rng));
            })
        }),
    );

    let mut rng = create_rng();
    c.bench(
        "key generation",
        Benchmark::new("Generate random keypair G2", move |b| {
            b.iter(|| {
                black_box(basic::key_pair_generate_g2(&mut rng));
            })
        }),
    );
}

fn curve_ops(c: &mut Criterion) {
    let mut rng = create_rng();
    let generator_g1 = ecp::ECP::generator();
    let generator_g2 = ecp2::ECP2::generator();

    let r = big::Big::new_ints(&rom::CURVE_ORDER);
    let s = big::Big::randomnum(&r, &mut rng);
    let s_copy = s.clone();

    let point_g1 = generator_g1.mul(&s);
    let point_g2 = generator_g2.mul(&s);
    assert!(!point_g1.is_infinity());
    assert!(!point_g2.is_infinity());

    c.bench(
        "multiplication",
        Benchmark::new("Multiply a point G1", move |b| {
            b.iter(|| {
                black_box(generator_g1.mul(&s));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "multiplication",
        Benchmark::new("Multiply a point G2", move |b| {
            b.iter(|| {
                black_box(generator_g2.mul(&s_copy));
            })
        })
        .sample_size(10),
    );

    let mut generator_g1 = ecp::ECP::generator();
    c.bench(
        "addition",
        Benchmark::new("Add two points G1", move |b| {
            b.iter(|| {
                black_box(generator_g1.add(&point_g1));
            })
        })
        .sample_size(10),
    );

    let mut generator_g2 = ecp2::ECP2::generator();
    c.bench(
        "addition",
        Benchmark::new("Add two points G2", move |b| {
            b.iter(|| {
                black_box(generator_g2.add(&point_g2));
            })
        })
        .sample_size(10),
    );
}

criterion_group!(
    benches,
    curve_ops,
    key_generation,
    basic_signing,
    aggregation,
    aggregate_verfication,
    serialisation_g1,
    serialisation_g2,
);
criterion_main!(benches);
