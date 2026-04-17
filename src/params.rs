//! Cryptographic parameters for the Rune protocol.
//!
//! All arithmetic operates in the polynomial ring:
//!
//!   R_q = Z_q[X] / (X^n + 1)
//!
//! where n = 256 and q = 998_244_353 (an NTT-friendly prime: 119 × 2^23 + 1).

use nc_polynomial::RingContext;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Ring parameters
// ---------------------------------------------------------------------------

/// Polynomial degree (power-of-two cyclotomic).
pub const N: usize = 256;

/// Coefficient modulus — NTT-friendly prime q = 998_244_353 = 119 × 2^23 + 1.
pub const Q: u64 = 998_244_353;

/// Primitive root of unity modulo q used by NTT.
pub const PRIMITIVE_ROOT: u64 = 3;

// ---------------------------------------------------------------------------
// Signature scheme parameters
// ---------------------------------------------------------------------------

/// Centered-binomial parameter for short secret / error polynomials.
/// Each coefficient is sampled as sum(η bits) − sum(η bits), giving values in [-η, η].
pub const ETA: u8 = 2;

/// Masking bound — uniform sampling range for commitment vectors.
/// Masking polynomials have coefficients in [−GAMMA, GAMMA].
pub const GAMMA: u64 = Q / 4;

/// Rejection sampling bound — signatures with ‖z‖_∞ ≥ BETA are discarded
/// to prevent secret leakage. We require BETA = GAMMA − ETA × N to ensure
/// that the response z = y + c·s remains within [−GAMMA, GAMMA] with high
/// probability when ‖c·s‖_∞ ≤ ETA × N (since c is sparse ternary and s is short).
pub const BETA: u64 = GAMMA - (ETA as u64) * (N as u64);

/// Hamming weight of the sparse ternary challenge polynomial.
/// The challenge c ∈ R_q has exactly KAPPA nonzero coefficients, each ±1.
pub const KAPPA: usize = 60;

/// Maximum number of signing attempts before aborting.
/// Each attempt may be rejected due to the norm bound on z.
pub const MAX_ATTEMPTS: usize = 256;

// ---------------------------------------------------------------------------
// Ring context singleton
// ---------------------------------------------------------------------------

/// Returns a validated `RingContext` for R_q = Z_q[X]/(X^256 + 1).
///
/// The context is constructed once and cached for the lifetime of the process.
/// It validates that q is NTT-friendly and that the primitive root is compatible
/// with the chosen cyclotomic polynomial.
pub fn ring_context() -> &'static RingContext {
    static CTX: OnceLock<RingContext> = OnceLock::new();
    CTX.get_or_init(|| {
        // Construct the modulus polynomial f(x) = x^256 + 1.
        // Coefficient representation: coeffs[0] = 1 (constant term),
        // coeffs[256] = 1 (leading term), all others zero.
        let mut modulus_poly = vec![0u64; N + 1];
        modulus_poly[0] = 1; // constant term
        modulus_poly[N] = 1; // x^N term

        RingContext::from_parts(N, Q, &modulus_poly, PRIMITIVE_ROOT)
            .expect("Rune: ring context construction must succeed with validated parameters")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameters_consistent() {
        assert!(N.is_power_of_two(), "n must be a power of two");
        assert!(BETA > 0, "rejection bound must be positive");
        assert!(KAPPA < N, "challenge weight must be less than n");
        assert!(
            GAMMA > (ETA as u64) * (N as u64),
            "masking bound must exceed secret norm bound"
        );
    }

    #[test]
    fn test_ring_context_builds() {
        let ctx = ring_context();
        assert_eq!(ctx.max_degree(), N);
        assert_eq!(ctx.modulus(), Q);
        assert_eq!(ctx.primitive_root(), PRIMITIVE_ROOT);
    }
}
