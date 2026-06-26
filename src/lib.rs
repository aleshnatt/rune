//! Rune ring signatures.
//!
//! `rune-ring` authenticates messages while hiding which member of a public
//! key ring produced the signature.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod core;
pub mod error;
pub mod keys;
pub mod params;

pub(crate) mod challenge;
pub(crate) mod math;

#[cfg(test)]
mod tests;

pub use core::{ring_sign, ring_verify, RingSignature};
pub use error::RuneError;
pub use keys::{generate_shared_a, keygen, PublicKey, SecretKey};
pub use math::Poly;
pub use params::{Params, RUNE_128, RUNE_256};
