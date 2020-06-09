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

#[derive(Deserialize)]
pub struct Field {
    pub m: String,
    pub p: String,
}

#[derive(Deserialize)]
pub struct Map {
    pub name: String,
}

#[derive(Deserialize)]
pub struct Point {
    pub x: String,
    pub y: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Bls12381Ro {
    pub L: String,
    pub Z: String,
    pub ciphersuite: String,
    pub curve: String,
    pub dst: String,
    pub expand: String,
    pub field: Field,
    pub hash: String,
    pub k: String,
    pub map: Map,
    pub randomOracle: bool,
    pub vectors: Vec<Bls12381RoVectors>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Bls12381RoVectors {
    pub P: Point,
    pub Q0: Point,
    pub Q1: Point,
    pub msg: String,
    pub u: Vec<String>,
}
