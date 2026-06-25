//! Key generation for Rune.

use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::error::RuneError;
use crate::math::{
    poly_add, poly_is_well_formed, poly_mul_schoolbook, sample_cbd, sample_uniform_poly, Poly,
    ZeroizingPoly,
};
use crate::params::Params;

/// Rune public key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey {
    /// Common public ring element shared by every member of a ring.
    pub a: Poly,
    /// Individual Ring-LWE public value `t = a * s + e`.
    pub t: Poly,
}

/// Rune secret key.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    s: Poly,
    e: Poly,
    t: Poly,
}

impl SecretKey {
    fn new(s: Poly, e: Poly, t: Poly) -> Self {
        Self { s, e, t }
    }

    pub(crate) fn s(&self) -> &Poly {
        &self.s
    }

    pub(crate) fn e(&self) -> &Poly {
        &self.e
    }

    pub(crate) fn t(&self) -> &Poly {
        &self.t
    }
}

// Redact secret material; show only the public component t.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("s", &"[REDACTED]")
            .field("e", &"[REDACTED]")
            .field("t", &"<public>")
            .finish()
    }
}

/// Generates the common public ring element from a CSPRNG.
pub fn generate_shared_a(params: &Params, rng: &mut (impl CryptoRng + RngCore)) -> Poly {
    sample_uniform_poly(params, rng)
}

/// Generates a Rune keypair.
///
/// # Errors
///
/// Returns [`RuneError::MalformedPublicKey`] if `a` is not a canonical
/// polynomial for `params`.
pub fn keygen(
    a: &Poly,
    params: &Params,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(PublicKey, SecretKey), RuneError> {
    if !poly_is_well_formed(a, params) {
        return Err(RuneError::MalformedPublicKey);
    }

    let s = ZeroizingPoly(sample_cbd(params, rng));
    let e = ZeroizingPoly(sample_cbd(params, rng));
    let t = poly_add(&poly_mul_schoolbook(a, &s.0, params), &e.0, params);

    let pk = PublicKey {
        a: a.clone(),
        t: t.clone(),
    };
    let sk = SecretKey::new(s.0.clone(), e.0.clone(), t);

    Ok((pk, sk))
}
