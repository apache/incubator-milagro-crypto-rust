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

/// BLS12-381
///
/// An implementation of BLS12-381 as specified by the following standard:
/// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
pub mod basic;
pub mod message_augmentation;
pub mod proof_of_possession;

// Expose helper functions for external libraries.
pub mod utils;

mod core;
mod iso;

#[cfg(target_pointer_width = "64")]
mod iso_constants_x64;
#[cfg(target_pointer_width = "64")]
pub(crate) use iso_constants_x64::{
    ISO11_XDEN, ISO11_XNUM, ISO11_YDEN, ISO11_YNUM, ISO3_XDEN, ISO3_XNUM, ISO3_YDEN, ISO3_YNUM,
};

#[cfg(target_pointer_width = "32")]
mod iso_constants_x32;
#[cfg(target_pointer_width = "32")]
pub(crate) use iso_constants_x32::{
    ISO11_XDEN, ISO11_XNUM, ISO11_YDEN, ISO11_YNUM, ISO3_XDEN, ISO3_XNUM, ISO3_YDEN, ISO3_YNUM,
};
