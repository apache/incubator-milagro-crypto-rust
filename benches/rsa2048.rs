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

use amcl::rand::RAND;
use amcl::rsa2048::{ff, rsa};
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

fn rsa(criterion: &mut Criterion) {
    let mut rng = create_rng();
    let mut pbc = rsa::new_public_key(ff::FFLEN);
    let mut prv = rsa::new_private_key(ff::HFLEN);
    let mut c: [u8; rsa::RFS] = [0; rsa::RFS];
    let mut m: [u8; rsa::RFS] = [0; rsa::RFS];
    let mut p: [u8; rsa::RFS] = [0; rsa::RFS];

    // Store copies for later
    let mut rng_copy = create_rng(); // Note this is deterministic so we can re-use this.
    let mut pbc_copy = rsa::new_public_key(ff::FFLEN);
    let mut prv_copy = rsa::new_private_key(ff::HFLEN);
    rsa::key_pair(&mut rng_copy, 65537, &mut prv_copy, &mut pbc_copy);

    criterion.bench(
        "rsa2048",
        Benchmark::new("Generate", move |b| {
            b.iter(|| {
                black_box(rsa::key_pair(&mut rng, 65537, &mut prv, &mut pbc));
            })
        })
        .sample_size(10),
    );

    for i in 0..rsa::RFS {
        m[i] = (i % 128) as u8;
    }

    criterion.bench(
        "rsa2048",
        Benchmark::new("Encrypt", move |b| {
            b.iter(|| {
                black_box(rsa::encrypt(&pbc_copy, &m, &mut c));
            })
        })
        .sample_size(10),
    );

    criterion.bench(
        "rsa2048",
        Benchmark::new("Decrypt", move |b| {
            b.iter(|| {
                black_box(rsa::decrypt(&prv_copy, &c, &mut p));
            })
        })
        .sample_size(10),
    );
}

criterion_group!(benches, rsa,);
criterion_main!(benches);
