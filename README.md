# Apache Milagro Crypto Library - Rust Version

## Updates

BLS12-381 has been updated to the the most recent standards being [bls-signatures-04](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04) and [hash-to-curve-09](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09).

Updated to Rust 2018.

This version of the library requires Version 1.31+ of Rust for the 2018 edition.

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

```
cargo bench --features bench
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
