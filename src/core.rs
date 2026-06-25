//! Ring signing and verification.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::challenge::{hash_chain, normalize_challenge, sample_challenge, validate_challenge};
use crate::error::RuneError;
use crate::keys::{PublicKey, SecretKey};
use crate::math::{
    poly_add, poly_infinity_norm, poly_is_well_formed, poly_mul_schoolbook, poly_sub,
    sample_bounded_poly, zero_poly, Poly, ZeroizingPoly,
};
use crate::params::Params;

/// A ring signature produced by [`ring_sign`].
///
/// The signature proves that one member of the ring signed the message without
/// revealing which member. Verification via [`ring_verify`] requires only the
/// ring's public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RingSignature {
    /// Secret response polynomials.
    pub z_s: Vec<Poly>,
    /// Error response polynomials.
    pub z_e: Vec<Poly>,
    /// Sequential challenge polynomials.
    pub c: Vec<Poly>,
}

/// Signs `message` with the secret key at `signer_index` in `ring`.
///
/// # Errors
///
/// Returns an error if the ring is malformed, the signer index is out of range,
/// the secret key does not match the signer public key, or rejection sampling
/// exceeds the configured attempt limit.
#[allow(clippy::many_single_char_names, clippy::similar_names)]
pub fn ring_sign(
    message: &[u8],
    signer_index: usize,
    sk: &SecretKey,
    ring: &[PublicKey],
    params: &Params,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<RingSignature, RuneError> {
    let k = ring.len();
    validate_ring(ring, params)?;

    if signer_index >= k {
        return Err(RuneError::SignerIndexOutOfRange);
    }
    if sk.t() != &ring[signer_index].t {
        return Err(RuneError::MalformedPublicKey);
    }

    let a = &ring[0].a;
    let response_bound = params.response_bound();

    // Expected iterations to acceptance: ~1 for RUNE_256, ~4 for RUNE_128.
    for _ in 0..params.max_attempts() {
        let y_s = ZeroizingPoly(sample_bounded_poly(params.gamma(), params, rng));
        let y_e = ZeroizingPoly(sample_bounded_poly(params.gamma(), params, rng));

        let mut z_s = vec![zero_poly(params); k];
        let mut z_e = vec![zero_poly(params); k];
        let mut c = vec![zero_poly(params); k];
        let mut w = vec![zero_poly(params); k];

        w[signer_index] = poly_add(&poly_mul_schoolbook(a, &y_s.0, params), &y_e.0, params);

        // The chain starts after the signer and closes immediately before it,
        // so c_pi is derived from the last simulated commitment.
        for j in 1..k {
            let i = (signer_index + j) % k;
            let prev = (i + k - 1) % k;
            let seed = hash_chain(message, ring, i, &w[prev], params);
            c[i] = sample_challenge(&seed, params);
            z_s[i] = sample_bounded_poly(response_bound - 1, params, rng);
            z_e[i] = sample_bounded_poly(response_bound - 1, params, rng);

            let az = poly_mul_schoolbook(a, &z_s[i], params);
            let az_plus_e = poly_add(&az, &z_e[i], params);
            let ct = poly_mul_schoolbook(&c[i], &ring[i].t, params);
            w[i] = poly_sub(&az_plus_e, &ct, params);
        }

        let prev = (signer_index + k - 1) % k;
        let seed = hash_chain(message, ring, signer_index, &w[prev], params);
        c[signer_index] = sample_challenge(&seed, params);

        let cs = ZeroizingPoly(poly_mul_schoolbook(&c[signer_index], sk.s(), params));
        let ce = ZeroizingPoly(poly_mul_schoolbook(&c[signer_index], sk.e(), params));
        z_s[signer_index] = poly_add(&y_s.0, &cs.0, params);
        z_e[signer_index] = poly_add(&y_e.0, &ce.0, params);

        if poly_infinity_norm(&z_s[signer_index]) >= response_bound
            || poly_infinity_norm(&z_e[signer_index]) >= response_bound
        {
            z_s[signer_index].zeroize();
            z_e[signer_index].zeroize();
            continue;
        }

        // y_s and y_e are zeroized here via ZeroizingPoly::drop.
        return Ok(RingSignature { z_s, z_e, c });
    }

    Err(RuneError::RejectionSamplingFailed)
}

/// Verifies a Rune ring signature.
///
/// # Errors
///
/// Returns an error if the ring or signature structure is malformed. Failed
/// cryptographic checks return `Ok(false)`.
pub fn ring_verify(
    message: &[u8],
    sig: &RingSignature,
    ring: &[PublicKey],
    params: &Params,
) -> Result<bool, RuneError> {
    let k = ring.len();
    validate_ring(ring, params)?;

    if sig.z_s.len() != k || sig.z_e.len() != k || sig.c.len() != k {
        return Err(RuneError::MalformedSignature);
    }

    let response_bound = params.response_bound();
    for i in 0..k {
        if !poly_is_well_formed(&sig.z_s[i], params)
            || !poly_is_well_formed(&sig.z_e[i], params)
            || !poly_is_well_formed(&sig.c[i], params)
        {
            return Err(RuneError::MalformedSignature);
        }
        if !validate_challenge(&sig.c[i], params) {
            return Ok(false);
        }
        if normalize_challenge(&sig.c[i], params) != sig.c[i] {
            return Ok(false);
        }
        if poly_infinity_norm(&sig.z_s[i]) >= response_bound
            || poly_infinity_norm(&sig.z_e[i]) >= response_bound
        {
            return Ok(false);
        }
    }

    let a = &ring[0].a;
    let mut commitments = vec![zero_poly(params); k];
    for (i, pk) in ring.iter().enumerate() {
        let az = poly_mul_schoolbook(a, &sig.z_s[i], params);
        let az_plus_e = poly_add(&az, &sig.z_e[i], params);
        let ct = poly_mul_schoolbook(&sig.c[i], &pk.t, params);
        commitments[i] = poly_sub(&az_plus_e, &ct, params);
    }

    for i in 0..k {
        let prev = (i + k - 1) % k;
        let seed = hash_chain(message, ring, i, &commitments[prev], params);
        let expected = sample_challenge(&seed, params);
        if !validate_challenge(&expected, params) {
            return Err(RuneError::MalformedChallenge);
        }
        if expected != sig.c[i] {
            return Ok(false);
        }
    }

    Ok(true)
}

fn validate_ring(ring: &[PublicKey], params: &Params) -> Result<(), RuneError> {
    if ring.len() < 2 {
        return Err(RuneError::RingTooSmall);
    }

    let a = &ring[0].a;
    if !poly_is_well_formed(a, params) {
        return Err(RuneError::MalformedPublicKey);
    }

    for pk in ring {
        if pk.a != *a {
            return Err(RuneError::InconsistentRingParameter);
        }
        if !poly_is_well_formed(&pk.a, params) || !poly_is_well_formed(&pk.t, params) {
            return Err(RuneError::MalformedPublicKey);
        }
    }

    Ok(())
}
