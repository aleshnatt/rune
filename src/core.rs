//! Core ring signature algorithms: `ring_sign` and `ring_verify`.
//!
//! Implements a lattice-based ring signature using the "Fiat-Shamir with
//! Aborts" paradigm over Ring-LWE. The signer produces a signature that
//! proves knowledge of a secret key corresponding to one of the public
//! keys in the ring, without revealing which one.
//!
//! # Protocol Overview
//!
//! **Signing** (signer at index π in a ring of k members):
//!
//! 1. For each non-signer i ≠ π: sample fake responses z_{s,i}, z_{e,i} and partial
//!    challenge c_i, compute simulated commitment w_i = a·z_{s,i} + z_{e,i} − c_i·t_i.
//! 2. For the signer π: sample masking y_s, y_e, compute real commitment w_π = a·y_s + y_e.
//! 3. Derive global challenge via Fiat-Shamir: seed = H(msg ‖ w_0 ‖ … ‖ w_{k−1}).
//! 4. Compute global challenge polynomial c from seed.
//! 5. Extract signer's partial challenge: c_π = c − Σ_{i≠π} c_i.
//! 6. Compute signer's responses: z_s = y_s + c_π · s_π, z_e = y_e + c_π · e_π.
//! 7. **Rejection sampling**: if ‖z_s‖_∞ ≥ β or ‖z_e‖_∞ ≥ β, discard and restart.
//!
//! **Verification**:
//!
//! 1. For each member i: recompute w_i' = a·z_{s,i} + z_{e,i} − c_i·t_i.
//! 2. Recompute seed' = H(msg ‖ w_0' ‖ … ‖ w_{k−1}').
//! 3. Recompute global challenge c' from seed'.
//! 4. Verify c' == Σ c_i (challenge consistency).
//! 5. Verify ‖z_i‖_∞ < β for all i (norm bound).

use nc_polynomial::{RingContext, RingElem};
use rand::{Rng, CryptoRng};

use crate::keys::{PublicKey, SecretKey};
use crate::math::{
    hash_to_challenge_seed, inf_norm, sample_challenge, sample_masking, sample_short,
};
use crate::params::{BETA, ETA, GAMMA, KAPPA, MAX_ATTEMPTS};

// ---------------------------------------------------------------------------
// Signature type
// ---------------------------------------------------------------------------

/// A Rune ring signature over a message, valid for a specific ring of public keys.
#[derive(Clone, Debug)]
pub struct RingSignature {
    /// Response polynomials z_{s,i} corresponding to the secret term.
    pub responses_s: Vec<RingElem>,
    /// Response polynomials z_{e,i} corresponding to the error term.
    pub responses_e: Vec<RingElem>,
    /// Partial challenge polynomials c_i for each ring member.
    pub challenges: Vec<RingElem>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during signing or verification.
#[derive(Debug)]
pub enum RingError {
    /// The signer index is out of bounds for the given ring.
    InvalidSignerIndex,
    /// The ring must contain at least 2 members.
    RingTooSmall,
    /// Rejection sampling exhausted all attempts without producing a valid signature.
    RejectionsExhausted,
    /// Signature has wrong number of components for the ring.
    SignatureSizeMismatch,
    /// A response polynomial exceeds the norm bound β.
    NormBoundExceeded,
    /// The challenge consistency check failed during verification.
    ChallengeVerificationFailed,
    /// Internal polynomial arithmetic error.
    ArithmeticError(String),
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RingError::InvalidSignerIndex => write!(f, "signer index out of bounds"),
            RingError::RingTooSmall => write!(f, "ring must have at least 2 members"),
            RingError::RejectionsExhausted => write!(f, "rejection sampling exhausted all attempts"),
            RingError::SignatureSizeMismatch => write!(f, "signature size does not match ring"),
            RingError::NormBoundExceeded => write!(f, "response norm exceeds bound β"),
            RingError::ChallengeVerificationFailed => write!(f, "challenge verification failed"),
            RingError::ArithmeticError(msg) => write!(f, "arithmetic error: {}", msg),
        }
    }
}

impl std::error::Error for RingError {}

// ---------------------------------------------------------------------------
// Ring signature generation
// ---------------------------------------------------------------------------

/// Produces a ring signature on `msg` using the signer's secret key.
///
/// The signer is at position `signer_index` within the ring of public keys.
/// The algorithm uses Fiat-Shamir with Aborts: if the computed response z_π
/// has infinity norm ≥ β, the attempt is discarded and the process restarts
/// with fresh randomness.
///
/// # Arguments
///
/// * `ctx` — validated ring context for R_q
/// * `msg` — the message to sign
/// * `sk` — the signer's secret key
/// * `signer_index` — position of the signer in the ring
/// * `ring_pks` — slice of all public keys in the ring (including the signer's)
/// * `rng` — cryptographic random number generator
///
/// # Returns
///
/// A `RingSignature` containing response and challenge polynomials for each
/// ring member, or a `RingError` if the signing fails.
pub fn ring_sign<R: Rng + CryptoRng>(
    ctx: &RingContext,
    msg: &[u8],
    sk: &SecretKey,
    signer_index: usize,
    ring_pks: &[PublicKey],
    rng: &mut R,
) -> Result<RingSignature, RingError> {
    let k = ring_pks.len();

    if k < 2 {
        return Err(RingError::RingTooSmall);
    }
    if signer_index >= k {
        return Err(RingError::InvalidSignerIndex);
    }

    // The shared public element a (must be the same for all ring members)
    let a = &ring_pks[0].a;

    for attempt in 0..MAX_ATTEMPTS {
        let _ = attempt; // suppress unused warning

        // ------------------------------------------------------------------
        // Step 1: Generate commitments for all ring members
        // ------------------------------------------------------------------

        let mut responses_s: Vec<RingElem> = Vec::with_capacity(k);
        let mut responses_e: Vec<RingElem> = Vec::with_capacity(k);
        let mut partial_challenges: Vec<RingElem> = Vec::with_capacity(k);
        let mut commitments: Vec<RingElem> = Vec::with_capacity(k);
        let mut masking_y_s: Option<RingElem> = None;
        let mut masking_y_e: Option<RingElem> = None;

        for (i, pk) in ring_pks.iter().enumerate() {
            if i == signer_index {
                // Real signer: sample masking polynomials y_s, y_e ← U([-γ, γ]^n)
                let y_s = sample_masking(ctx, GAMMA, rng);
                let y_e = sample_masking(ctx, GAMMA, rng);

                // Commitment: w_π = a · y_s + y_e
                let a_ys = a
                    .mul(&y_s)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
                let w = a_ys
                    .add(&y_e)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;

                commitments.push(w);
                // Placeholder — will be filled later
                responses_s.push(ctx.zero_element());
                responses_e.push(ctx.zero_element());
                partial_challenges.push(ctx.zero_element());
                masking_y_s = Some(y_s);
                masking_y_e = Some(y_e);
            } else {
                // Non-signer i: simulate with random responses and challenge
                let z_si = sample_masking(ctx, GAMMA - 1, rng);
                let z_ei = sample_masking(ctx, GAMMA - 1, rng);
                let c_i = sample_short(ctx, ETA, rng);

                // Simulated commitment: w_i = a·z_si + z_ei − c_i·t_i
                let az_s = a
                    .mul(&z_si)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
                let az_s_e = az_s
                    .add(&z_ei)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
                let ct = c_i
                    .mul(&pk.t)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
                let w_i = az_s_e
                    .sub(&ct)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;

                commitments.push(w_i);
                responses_s.push(z_si);
                responses_e.push(z_ei);
                partial_challenges.push(c_i);
            }
        }

        // ------------------------------------------------------------------
        // Step 2: Derive global challenge via Fiat-Shamir
        // ------------------------------------------------------------------

        let seed = hash_to_challenge_seed(msg, &commitments);
        let global_challenge = sample_challenge(ctx, &seed, KAPPA);

        // ------------------------------------------------------------------
        // Step 3: Extract signer's partial challenge
        // c_π = c − Σ_{i≠π} c_i
        // ------------------------------------------------------------------

        let mut sum_other_challenges = ctx.zero_element();
        for (i, pc) in partial_challenges.iter().enumerate() {
            if i != signer_index {
                sum_other_challenges = sum_other_challenges
                    .add(pc)
                    .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
            }
        }

        let c_signer = global_challenge
            .sub(&sum_other_challenges)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;

        // ------------------------------------------------------------------
        // Step 4: Compute signer's responses
        // z_s = y_s + c_π · s_π,   z_e = y_e + c_π · e_π
        // ------------------------------------------------------------------

        let y_s = masking_y_s.as_ref().unwrap();
        let y_e = masking_y_e.as_ref().unwrap();
        let cs = c_signer
            .mul(&sk.s)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let ce = c_signer
            .mul(&sk.e)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let z_signer_s = y_s
            .add(&cs)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let z_signer_e = y_e
            .add(&ce)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;

        // ------------------------------------------------------------------
        // Step 5: Rejection sampling
        // If ‖z_s‖_∞ ≥ β or ‖z_e‖_∞ ≥ β, abort this attempt and retry
        // ------------------------------------------------------------------

        if inf_norm(&z_signer_s) >= BETA || inf_norm(&z_signer_e) >= BETA {
            continue; // ABORT — restart with fresh randomness
        }

        // ------------------------------------------------------------------
        // Step 6: Assemble final signature
        // ------------------------------------------------------------------

        responses_s[signer_index] = z_signer_s;
        responses_e[signer_index] = z_signer_e;
        partial_challenges[signer_index] = c_signer;

        return Ok(RingSignature {
            responses_s,
            responses_e,
            challenges: partial_challenges,
        });
    }

    Err(RingError::RejectionsExhausted)
}

// ---------------------------------------------------------------------------
// Ring signature verification
// ---------------------------------------------------------------------------

/// Verifies a Rune ring signature against a message and ring of public keys.
///
/// # Verification Steps
///
/// 1. For each ring member i, recompute the commitment:
///    w_i' = a·z_{s,i} + z_{e,i} − c_i·t_i
/// 2. Recompute the Fiat-Shamir challenge seed from the commitments.
/// 3. Derive the expected global challenge c' from the seed.
/// 4. Verify that c' equals the sum of all partial challenges.
/// 5. Verify that all response polynomials satisfy ‖z_i‖_∞ < β.
///
/// # Returns
///
/// `Ok(true)` if the signature is valid, `Err(RingError)` if a structural
/// error is detected (wrong sizes, arithmetic failure, etc.), or `Ok(false)`
/// if the cryptographic checks fail.
pub fn ring_verify(
    ctx: &RingContext,
    msg: &[u8],
    sig: &RingSignature,
    ring_pks: &[PublicKey],
) -> Result<bool, RingError> {
    let k = ring_pks.len();

    if k < 2 {
        return Err(RingError::RingTooSmall);
    }
    if sig.responses_s.len() != k || sig.responses_e.len() != k || sig.challenges.len() != k {
        return Err(RingError::SignatureSizeMismatch);
    }

    let a = &ring_pks[0].a;

    // ------------------------------------------------------------------
    // Step 1: Norm bound check on all responses
    // ------------------------------------------------------------------

    for i in 0..k {
        if inf_norm(&sig.responses_s[i]) >= BETA || inf_norm(&sig.responses_e[i]) >= BETA {
            return Ok(false);
        }
    }

    // ------------------------------------------------------------------
    // Step 2: Recompute commitments w_i' = a·z_{s,i} + z_{e,i} − c_i·t_i
    // ------------------------------------------------------------------

    let mut commitments: Vec<RingElem> = Vec::with_capacity(k);

    for (i, pk) in ring_pks.iter().enumerate() {
        let az_s = a
            .mul(&sig.responses_s[i])
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let az_s_e = az_s
            .add(&sig.responses_e[i])
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let ct = sig.challenges[i]
            .mul(&pk.t)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        let w_i = az_s_e
            .sub(&ct)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
        commitments.push(w_i);
    }

    // ------------------------------------------------------------------
    // Step 3: Recompute global challenge from commitments
    // ------------------------------------------------------------------

    let seed = hash_to_challenge_seed(msg, &commitments);
    let expected_challenge = sample_challenge(ctx, &seed, KAPPA);

    // ------------------------------------------------------------------
    // Step 4: Verify challenge consistency: c' == Σ c_i
    // ------------------------------------------------------------------

    let mut sum_challenges = ctx.zero_element();
    for c_i in &sig.challenges {
        sum_challenges = sum_challenges
            .add(c_i)
            .map_err(|e| RingError::ArithmeticError(format!("{:?}", e)))?;
    }

    if expected_challenge != sum_challenges {
        return Ok(false);
    }

    Ok(true)
}
