//! Polynomial arithmetic utilities and sampling routines for the Rune protocol.
//!
//! All operations are performed over the ring R_q = Z_q[X]/(X^n + 1)
//! using `nc_polynomial::RingContext` for validated ring-element construction
//! and modular reduction.

use nc_polynomial::{RingContext, RingElem};
use rand::{Rng, CryptoRng};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::params::{N, Q};

// ---------------------------------------------------------------------------
// Modular arithmetic helpers
// ---------------------------------------------------------------------------

/// Maps a signed value into [0, q) representation.
///
/// For x ≥ 0: returns x mod q.
/// For x < 0: returns q − (|x| mod q), which is the canonical representative.
fn wrap_signed_to_modulus(x: i64, q: u64) -> u64 {
    let q_i = q as i64;
    ((x % q_i + q_i) % q_i) as u64
}

/// Computes the centered representative of a coefficient.
///
/// Maps c ∈ [0, q) to the centered range [−(q−1)/2, (q−1)/2] and returns
/// the absolute value. This gives the infinity-norm contribution of that
/// coefficient.
fn centered_abs(c: u64, q: u64) -> u64 {
    let half = q / 2;
    if c > half {
        q - c
    } else {
        c
    }
}

// ---------------------------------------------------------------------------
// Norm computation
// ---------------------------------------------------------------------------

/// Computes the infinity norm (ℓ_∞) of a ring element in centered representation.
///
/// For each coefficient c_i ∈ [0, q), we compute |c_i|_q = min(c_i, q − c_i),
/// which is the centered absolute value, and return the maximum over all
/// coefficients.
pub fn inf_norm(elem: &RingElem) -> u64 {
    let q = elem.params().modulus();
    elem.coefficients()
        .iter()
        .map(|&c| centered_abs(c, q))
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Polynomial sampling
// ---------------------------------------------------------------------------

/// Samples a uniformly random polynomial from R_q.
///
/// Each coefficient is independently sampled from [0, q) using rejection
/// sampling to avoid modular bias.
pub fn sample_uniform<R: Rng + CryptoRng>(ctx: &RingContext, rng: &mut R) -> RingElem {
    let mut coeffs = vec![0u64; N + 1];
    for coeff in coeffs.iter_mut().take(N) {
        // Rejection sampling: draw u64, reject if ≥ largest multiple of q
        // that fits in u64. This eliminates modular bias.
        loop {
            let sample: u64 = rng.random();
            // Compute the largest multiple of Q that fits in u64
            let max_acceptable = u64::MAX - (u64::MAX % Q);
            if sample < max_acceptable {
                *coeff = sample % Q;
                break;
            }
        }
    }
    ctx.element(&coeffs)
        .expect("uniform sampling: coefficients are within bounds")
}

/// Samples a short polynomial using the centered binomial distribution CBD(η).
///
/// Each coefficient is computed as:
///   c_i = Σ_{j=1}^{η} a_j − Σ_{j=1}^{η} b_j
///
/// where a_j, b_j are independent uniform bits. This yields coefficients
/// in the range [−η, η] with a binomial distribution centered at zero.
pub fn sample_short<R: Rng + CryptoRng>(ctx: &RingContext, eta: u8, rng: &mut R) -> RingElem {
    let mut coeffs = vec![0u64; N + 1];
    for coeff in coeffs.iter_mut().take(N) {
        let mut a: i64 = 0;
        let mut b: i64 = 0;
        for _ in 0..eta {
            a += (rng.random::<u32>() & 1) as i64;
            b += (rng.random::<u32>() & 1) as i64;
        }
        *coeff = wrap_signed_to_modulus(a - b, Q);
    }
    ctx.element(&coeffs)
        .expect("short sampling: coefficients are within bounds")
}

/// Samples a masking polynomial with coefficients uniform in [−γ, γ].
///
/// This is used to produce the commitment values y_i in the signing protocol.
/// The masking must be large enough to hide the secret s when added to c·s,
/// but bounded enough that the rejection sampling step succeeds with
/// reasonable probability.
pub fn sample_masking<R: Rng + CryptoRng>(ctx: &RingContext, gamma: u64, rng: &mut R) -> RingElem {
    let range = 2 * gamma + 1; // number of values in [-gamma, gamma]
    let mut coeffs = vec![0u64; N + 1];
    for coeff in coeffs.iter_mut().take(N) {
        // Sample uniformly in [0, range) using rejection sampling built into rand
        let sample = rng.random_range(0..range);
        let signed = sample as i64 - gamma as i64;
        *coeff = wrap_signed_to_modulus(signed, Q);
    }
    ctx.element(&coeffs)
        .expect("masking sampling: coefficients are within bounds")
}

/// Derives a sparse ternary challenge polynomial from a seed using SHAKE-256.
///
/// The challenge c has exactly `kappa` nonzero coefficients, each ±1.
/// Positions are selected by rejection-sampling indices from the SHAKE-256
/// output stream, and signs are determined by the least significant bit
/// of each subsequent output byte.
///
/// This is the deterministic Fiat-Shamir oracle: given the same seed,
/// it always produces the same challenge polynomial.
pub fn sample_challenge(ctx: &RingContext, seed: &[u8], kappa: usize) -> RingElem {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut coeffs = vec![0u64; N + 1];
    let mut positions_set = vec![false; N];
    let mut placed = 0;

    while placed < kappa {
        // Read 2 bytes for position (rejection sample to [0, N))
        let mut pos_bytes = [0u8; 2];
        reader.read(&mut pos_bytes);
        let pos = u16::from_le_bytes(pos_bytes) as usize;

        if pos >= N || positions_set[pos] {
            continue; // reject and resample
        }

        // Read 1 byte for sign
        let mut sign_byte = [0u8; 1];
        reader.read(&mut sign_byte);
        let sign = if sign_byte[0] & 1 == 0 { 1i64 } else { -1i64 };

        coeffs[pos] = wrap_signed_to_modulus(sign, Q);
        positions_set[pos] = true;
        placed += 1;
    }

    ctx.element(&coeffs)
        .expect("challenge sampling: coefficients are within bounds")
}

// ---------------------------------------------------------------------------
// Fiat-Shamir hash oracle
// ---------------------------------------------------------------------------

/// Computes the Fiat-Shamir challenge seed: H(msg ‖ w_0 ‖ w_1 ‖ … ‖ w_{k−1}).
///
/// Each commitment w_i is serialized as its full coefficient vector (N × 8 bytes
/// in little-endian u64 encoding), and the message is prepended.
/// The output is a 64-byte SHAKE-256 digest used as the seed for
/// `sample_challenge`.
pub fn hash_to_challenge_seed(msg: &[u8], commitments: &[RingElem]) -> Vec<u8> {
    let mut hasher = Shake256::default();

    // Domain separator
    hasher.update(b"Rune-RING-SIG-v1");

    // Message length prefix (8 bytes LE) + message body
    hasher.update(&(msg.len() as u64).to_le_bytes());
    hasher.update(msg);

    // Each commitment polynomial
    for w in commitments {
        let coeffs = w.coefficients();
        for &c in coeffs {
            hasher.update(&c.to_le_bytes());
        }
    }

    let mut reader = hasher.finalize_xof();
    let mut seed = vec![0u8; 64];
    reader.read(&mut seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ring_context;

    #[test]
    fn test_inf_norm_zero() {
        let ctx = ring_context();
        let zero = ctx.zero_element();
        assert_eq!(inf_norm(&zero), 0);
    }

    #[test]
    fn test_sample_uniform_in_range() {
        let ctx = ring_context();
        let mut rng = rand::rng();
        let poly = sample_uniform(ctx, &mut rng);
        for &c in poly.coefficients() {
            assert!(c < Q, "coefficient must be < q");
        }
    }

    #[test]
    fn test_sample_short_bounded() {
        let ctx = ring_context();
        let mut rng = rand::rng();
        let poly = sample_short(ctx, 2, &mut rng);
        let norm = inf_norm(&poly);
        assert!(
            norm <= 2,
            "CBD(2) coefficients must be in [-2, 2], got norm {}",
            norm
        );
    }

    #[test]
    fn test_sample_challenge_weight() {
        let ctx = ring_context();
        let seed = b"test-challenge-seed-0123456789ab";
        let c = sample_challenge(ctx, seed, 60);
        let nonzero_count = c
            .coefficients()
            .iter()
            .filter(|&&coeff| coeff != 0)
            .count();
        assert_eq!(nonzero_count, 60, "challenge must have exactly κ nonzero coefficients");
    }

    #[test]
    fn test_sample_challenge_ternary() {
        let ctx = ring_context();
        let seed = b"test-challenge-seed-0123456789ab";
        let c = sample_challenge(ctx, seed, 60);
        for &coeff in c.coefficients() {
            // Must be 0, 1, or q-1 (which represents -1)
            assert!(
                coeff == 0 || coeff == 1 || coeff == Q - 1,
                "challenge coefficient must be 0, 1, or -1 (mod q), got {}",
                coeff
            );
        }
    }

    #[test]
    fn test_hash_deterministic() {
        let ctx = ring_context();
        let elem = ctx.zero_element();
        let seed1 = hash_to_challenge_seed(b"hello", std::slice::from_ref(&elem));
        let seed2 = hash_to_challenge_seed(b"hello", std::slice::from_ref(&elem));
        assert_eq!(seed1, seed2, "same inputs must produce same seed");
    }
}
