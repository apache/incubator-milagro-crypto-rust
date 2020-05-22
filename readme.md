# Apache Milagro Crypto Library - Rust Version

## Updates

BLS12-381 has been updated to the the most recent standards being [bls-signatures-02](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02) and [hash-to-curve-07](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07).

Updated to Rust 2018.

This version of the library requires Version 1.31+ of Rust for 64-bit
integer support and for Rust 2018.

AMCL version 2 is distributed as a cargo crate.

Modulues (namespaces) are used to separate different curves.

## Testing

Unit testing can be done using cargo testing framework.

Note: `--all-features` may be replaced by `--features xx` where `xx` is
the desired feature e.g. `bls381`.

```
cargo test --all --all-features --release
```

## Benchmarking

To build the library and see it in action, copy all of the files in this
directory and its subdirectories to a fresh root directory.

Then for example execute
```
cargo build --release --features "bn254 bls383 bls24 bls48 ed25519 nist256 goldilocks rsa2048"
```
This will create a build of the library for the current default target (be it 32 or 64 bits).

(To test a 32-bit environment you can follow the Web Assembly (wasm) readme instructions for rust)

Next copy the library from `target/release/libamcl.rlib` into the root
directory and execute
```
rustc BenchtestALL.rs --extern amcl=libamcl.rlib
```

Finally execute these programs.

To add amcl functionality to your own programs, add a dependency to your
`Cargo.toml` file. For example to use the curve bls48, add this dependency

```
[dependencies]
amcl = { version = "0.2.0",  optional = true, default-features = false, features = ["bls48"]}
```

If published to crates.io, or

```
amcl = { version = "0.2.0",  optional = true, default-features = false, features = ["bls48"], path="your_amcl_location" }
```

And to use primitives of the needed curve in your source code:

```
use amcl::bls48::{ECP, ECP8}; // any primitive you need
```

## Features and Protocol

* Elliptic Curves
  * ed25519
  * c25519
  * nist256
  * brainpool
  * anssi
  * hifive
  * goldilocks
  * nist384
  * c41417
  * nist521
  * nums256w
  * nums256e
  * nums384w
  * nums384e
  * nums512w
  * nums512e
  * secp256k1
* Pairing-Friendly Elliptic Curves
  * bn254
  * bn254cx
  * fp256bn
  * fp512bn
  * bls383
  * bls381
  * bls461
  * bls24
  * bls48
* RSA
  * rsa2048
  * rsa3072
  * rsa4096
* SHA-2
  * SHA2-256
  * SHA2-384
  * SHA2-512
* SHA-3
  * SHA3-224
  * SHA3-256
  * SHA3-384
  * SHA3-512
  * SHAKE-128
  * SHAKE-256

Note `SHA-2` and `SHA-3` features will always be compiled however all other features require
the feature flag `--features xx`
