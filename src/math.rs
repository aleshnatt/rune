//! Polynomial arithmetic and sampling.

use std::ops::Index;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::RuneError;
use crate::params::Params;

/// Maximum polynomial degree supported by this implementation.
pub(crate) const MAX_N: usize = 512;

/// A polynomial in `R_q = Z_q[X]/(X^n + 1)`, stored as a centered coefficient
/// vector for the active parameter set.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct Poly(pub(crate) Vec<i64>);

impl Poly {
    /// Builds a polynomial from centered coefficients.
    ///
    /// # Errors
    ///
    /// Returns [`RuneError::MalformedPublicKey`] if `coefficients` does not
    /// match `params.n()` or contains a non-canonical coefficient.
    pub fn from_coefficients(
        coefficients: impl Into<Vec<i64>>,
        params: &Params,
    ) -> Result<Self, RuneError> {
        let poly = Self(coefficients.into());
        if poly_is_well_formed(&poly, params) {
            Ok(poly)
        } else {
            Err(RuneError::MalformedPublicKey)
        }
    }

    /// Returns the number of stored coefficients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the polynomial has no coefficients.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrows the centered coefficient vector.
    #[must_use]
    pub fn coefficients(&self) -> &[i64] {
        &self.0
    }

    pub(crate) fn coefficients_mut(&mut self) -> &mut [i64] {
        &mut self.0
    }
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Poly(n={}, ||.||_inf={})",
            self.0.len(),
            self.0
                .iter()
                .map(|coeff| i64::saturating_abs(*coeff))
                .max()
                .unwrap_or(0)
        )
    }
}

impl Index<usize> for Poly {
    type Output = i64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Wrapper that zeroizes polynomial storage on drop.
pub(crate) struct ZeroizingPoly(pub(crate) Poly);

impl Drop for ZeroizingPoly {
    fn drop(&mut self) {
        // Keep secret-derived coefficients out of long-lived heap storage.
        self.0 .0.zeroize();
    }
}

pub(crate) fn zero_poly(params: &Params) -> Poly {
    Poly(vec![0; params.n()])
}

pub(crate) fn poly_reduce_mod_q(x: i128, q: i64) -> i64 {
    let modulus = i128::from(q);
    let mut reduced = x % modulus;
    if reduced < 0 {
        reduced += modulus;
    }

    let half = modulus / 2;
    if reduced > half {
        reduced -= modulus;
    }

    i64::try_from(reduced).expect("centered residue fits in i64")
}

pub(crate) fn poly_is_well_formed(poly: &Poly, params: &Params) -> bool {
    if poly.0.len() != params.n() {
        return false;
    }

    let half_q = (params.q() - 1) / 2;
    poly.0
        .iter()
        .all(|coeff| (-half_q..=half_q).contains(coeff))
}

pub(crate) fn poly_add(a: &Poly, b: &Poly, params: &Params) -> Poly {
    let coeffs =
        a.0.iter()
            .zip(&b.0)
            .map(|(lhs, rhs)| poly_reduce_mod_q(i128::from(*lhs) + i128::from(*rhs), params.q()))
            .collect();
    Poly(coeffs)
}

pub(crate) fn poly_sub(a: &Poly, b: &Poly, params: &Params) -> Poly {
    let coeffs =
        a.0.iter()
            .zip(&b.0)
            .map(|(lhs, rhs)| poly_reduce_mod_q(i128::from(*lhs) - i128::from(*rhs), params.q()))
            .collect();
    Poly(coeffs)
}

/// Multiplies two polynomials in `R_q = Z_q[X]/(X^n + 1)`.
///
/// # Performance
///
/// This is an O(n²) schoolbook implementation. For n=512 (`RUNE_256`),
/// signing is slower than an NTT-based implementation would be.
/// NTT support for q=8380417 is planned for a future release.
pub(crate) fn poly_mul_schoolbook(a: &Poly, b: &Poly, params: &Params) -> Poly {
    let n = params.n();
    let mut acc = vec![0_i128; n];

    for (i, a_coeff) in a.0.iter().enumerate() {
        for (j, b_coeff) in b.0.iter().enumerate() {
            let product = i128::from(*a_coeff) * i128::from(*b_coeff);
            let degree = i + j;
            if degree < n {
                acc[degree] += product;
            } else {
                acc[degree - n] -= product;
            }
        }
    }

    Poly(
        acc.into_iter()
            .map(|coeff| poly_reduce_mod_q(coeff, params.q()))
            .collect(),
    )
}

/// Computes the infinity norm of a polynomial.
///
/// This function is not constant-time and must not be called on secret values
/// where timing leakage is within the caller's threat model.
/// Coefficient values of [`i64::MIN`] are handled via saturating absolute value
/// and will report a norm of [`i64::MAX`], which always fails the rejection
/// bound check.
pub(crate) fn poly_infinity_norm(a: &Poly) -> i64 {
    a.0.iter()
        .map(|coeff| i64::saturating_abs(*coeff))
        .max()
        .unwrap_or(0)
}

pub(crate) fn sample_uniform_poly(params: &Params, rng: &mut (impl CryptoRng + RngCore)) -> Poly {
    let q_u = u64::try_from(params.q()).expect("modulus is positive");
    let max_acceptable = u64::MAX - (u64::MAX % q_u);
    let mut coeffs = Vec::with_capacity(params.n());

    for _ in 0..params.n() {
        loop {
            let sample = rng.next_u64();
            if sample < max_acceptable {
                coeffs.push(poly_reduce_mod_q(i128::from(sample % q_u), params.q()));
                break;
            }
        }
    }

    Poly(coeffs)
}

pub(crate) fn sample_cbd(params: &Params, rng: &mut (impl CryptoRng + RngCore)) -> Poly {
    let mut coeffs = Vec::with_capacity(params.n());

    for _ in 0..params.n() {
        let mut lhs = 0_i64;
        let mut rhs = 0_i64;
        for _ in 0..params.eta() {
            lhs += i64::from(rng.next_u32() & 1);
            rhs += i64::from(rng.next_u32() & 1);
        }
        coeffs.push(lhs - rhs);
    }

    Poly(coeffs)
}

pub(crate) fn sample_bounded_poly(
    bound: i64,
    params: &Params,
    rng: &mut (impl CryptoRng + RngCore),
) -> Poly {
    let range = u64::try_from(2 * bound + 1).expect("bound is positive");
    let mut coeffs = Vec::with_capacity(params.n());

    for _ in 0..params.n() {
        let sample = sample_below(range, rng);
        let signed = i64::try_from(sample).expect("range fits in i64") - bound;
        coeffs.push(poly_reduce_mod_q(i128::from(signed), params.q()));
    }

    Poly(coeffs)
}

fn sample_below(bound: u64, rng: &mut (impl CryptoRng + RngCore)) -> u64 {
    let max_acceptable = u64::MAX - (u64::MAX % bound);
    loop {
        let sample = rng.next_u64();
        if sample < max_acceptable {
            return sample % bound;
        }
    }
}
