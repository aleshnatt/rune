//! # Rune — A Lattice-based Blind Relay Protocol
//!
//! Rune implements a Post-Quantum Ring Signature scheme over Ring-LWE
//! (Learning With Errors) for blind relay transport privacy. The scheme
//! uses the "Fiat-Shamir with Aborts" paradigm to prevent secret key
//! leakage through rejection sampling.
//!
//! ## Algebraic Structure
//!
//! All operations are performed in the polynomial ring:
//!
//! ```text
//!   R_q = Z_q[X] / (X^256 + 1)
//! ```
//!
//! where q = 998,244,353 (an NTT-friendly prime).
//!
//! ## Usage
//!
//! ```rust
//! use rune::params::ring_context;
//! use rune::keys::{generate_shared_a, keygen};
//! use rune::core::{ring_sign, ring_verify};
//!
//! let ctx = ring_context();
//! let mut rng = rand::rng();
//! let a = generate_shared_a(ctx, &mut rng);
//!
//! // Generate ring of 3 members
//! let (sk0, pk0) = keygen(ctx, &a, &mut rng);
//! let (sk1, pk1) = keygen(ctx, &a, &mut rng);
//! let (sk2, pk2) = keygen(ctx, &a, &mut rng);
//!
//! let ring = vec![pk0, pk1.clone(), pk2];
//! let msg = b"blind relay payload";
//!
//! // Member 1 signs
//! let sig = ring_sign(ctx, msg, &sk1, 1, &ring, &mut rng).unwrap();
//!
//! // Anyone can verify
//! assert!(ring_verify(ctx, msg, &sig, &ring).unwrap());
//! ```

pub mod core;
pub mod keys;
pub mod math;
pub mod params;
