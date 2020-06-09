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

use amcl::goldilocks::*;
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

fn curve_ops(c: &mut Criterion) {
    let mut rng = create_rng();
    let generator = ecp::ECP::generator();

    let r = big::Big::new_ints(&rom::CURVE_ORDER);
    let s = big::Big::randomnum(&r, &mut rng);

    let point = generator.mul(&r);
    assert!(point.is_infinity());

    c.bench(
        "multiplication",
        Benchmark::new("Multiply a point", move |b| {
            b.iter(|| {
                black_box(generator.mul(&s));
            })
        })
        .sample_size(10),
    );

    let mut generator = ecp::ECP::generator();
    c.bench(
        "add",
        Benchmark::new("Add two points", move |b| {
            b.iter(|| {
                black_box(generator.add(&point));
            })
        })
        .sample_size(10),
    );

    let mut generator = ecp::ECP::generator();
    let generator_copy = ecp::ECP::generator();
    c.bench(
        "double",
        Benchmark::new("Double a points", move |b| {
            b.iter(|| {
                black_box(generator.add(&generator_copy));
            })
        })
        .sample_size(10),
    );
}

criterion_group!(benches, curve_ops,);
criterion_main!(benches);
