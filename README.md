# rune-ring

[![crates.io](https://img.shields.io/crates/v/rune-ring.svg)](https://crates.io/crates/rune-ring)
[![docs.rs](https://docs.rs/rune-ring/badge.svg)](https://docs.rs/rune-ring)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Rune is a Rust ring signature library for authenticating a message while hiding which member of a public key ring produced the signature.

## What is a Ring Signature

A ring signature lets one member of a public key set sign a message so that a verifier knows the signer belongs to the set, but cannot determine which member signed. The signer does not need coordination from the other ring members; their public keys are enough to build the anonymity set.

Rune uses lattice-based polynomial arithmetic with a sequential challenge chain and Fiat-Shamir hashing.

## Security Notice

`RUNE_128` provides approximately 10 bits of classical security and must not be used in production. It exists for testing and performance measurement only.

`RUNE_256` is the default parameter set and targets approximately 128 bits of classical security.

The implementation has not received a professional cryptographic audit. Use in production systems requires independent review.

`infinity_norm` is not constant-time and is a known timing side-channel.

## Quick Start

```rust
use rune_ring::{generate_shared_a, keygen, ring_sign, ring_verify};
use rune_ring::params::RUNE_256;
use rand::rngs::OsRng;

fn main() -> Result<(), rune_ring::RuneError> {
    let params = &RUNE_256;
    // RUNE_256 targets ~128-bit classical security.
    let mut rng = OsRng;

    let a = generate_shared_a(params, &mut rng);

    let (pk0, sk0) = keygen(&a, params, &mut rng)?;
    let (pk1, _sk1) = keygen(&a, params, &mut rng)?;
    let (pk2, _sk2) = keygen(&a, params, &mut rng)?;

    let ring = vec![pk0.clone(), pk1, pk2];
    let message = b"authenticated relay handshake";

    let sig = ring_sign(message, 0, &sk0, &ring, params, &mut rng)?;
    let valid = ring_verify(message, &sig, &ring, params)?;
    assert!(valid);
    Ok(())
}
```

## Parameter Sets

| Name | Security | q | Proof Size |
| --- | --- | --- | --- |
| `RUNE_128` | Approximately 10 bits, DO NOT USE IN PRODUCTION | 998244353 | `O(k * n)` |
| `RUNE_256` | Approximately 128 bits classical security | 8380417 | `O(k * n)` |

## Building and Testing

```bash
cargo build --release
cargo test
cargo bench
```

## License

MIT OR Apache-2.0
