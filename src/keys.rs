//! Key generation for the Rune protocol.
//!
//! Each participant in the ring generates a keypair (sk, pk) where:
//!
//!   sk = s           ← CBD(η),  a short secret polynomial
//!   pk = (a, t)      where t = a·s + e,  a ∈ R_q uniform (shared),
//!                    e ← CBD(η) is a short error polynomial.
//!
//! The public element `a` is a system-wide parameter shared by all ring
//! members. Each member independently samples their own (s_i, e_i) to
//! produce their public key t_i = a·s_i + e_i.

use nc_polynomial::{RingContext, RingElem};
use rand::Rng;

use crate::math::{sample_short, sample_uniform};
use crate::params::ETA;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Secret key: a short polynomial s ∈ R_q with ‖s‖_∞ ≤ η.
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// The secret polynomial sampled from CBD(η).
    pub s: RingElem,
    /// The error polynomial sampled from CBD(η).
    pub e: RingElem,
}

/// Public key: the shared uniform element a and the individual RLWE
/// sample t = a·s + e.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// System-wide uniform polynomial (shared across the ring).
    pub a: RingElem,
    /// Individual public polynomial: t = a·s + e.
    pub t: RingElem,
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generates an RLWE keypair for one ring member.
///
/// The caller provides the shared public element `a`. If this is the first
/// member, `a` should be freshly sampled via `sample_uniform`; subsequent
/// members reuse the same `a`.
///
/// # Returns
///
/// A tuple `(SecretKey, PublicKey)` where:
/// - `SecretKey.s` is a short polynomial (CBD with η = 2)
/// - `PublicKey.a` is the shared ring element
/// - `PublicKey.t = a·s + e` where e is independently sampled CBD(η)
pub fn keygen<R: Rng>(ctx: &RingContext, a: &RingElem, rng: &mut R) -> (SecretKey, PublicKey) {
    // Sample short secret polynomial s ← CBD(η)
    let s = sample_short(ctx, ETA, rng);

    // Sample short error polynomial e ← CBD(η)
    let e = sample_short(ctx, ETA, rng);

    // Compute public key: t = a·s + e  (in R_q)
    let t = a
        .mul(&s)
        .expect("keygen: polynomial multiplication must succeed")
        .add(&e)
        .expect("keygen: polynomial addition must succeed");

    let sk = SecretKey { s, e };
    let pk = PublicKey {
        a: a.clone(),
        t,
    };

    (sk, pk)
}

/// Generates a fresh shared public element `a ← U(R_q)`.
///
/// This should be called once to establish the system parameter,
/// then distributed to all ring participants.
pub fn generate_shared_a<R: Rng>(ctx: &RingContext, rng: &mut R) -> RingElem {
    sample_uniform(ctx, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::inf_norm;
    use crate::params::{ring_context, ETA, Q};

    #[test]
    fn test_keygen_produces_valid_keys() {
        let ctx = ring_context();
        let mut rng = rand::rng();
        let a = generate_shared_a(ctx, &mut rng);
        let (sk, pk) = keygen(ctx, &a, &mut rng);

        // Secret key should be short
        assert!(
            inf_norm(&sk.s) <= ETA as u64,
            "secret key norm must be ≤ η"
        );

        // Public key polynomial `a` must match the shared element
        assert_eq!(pk.a, a, "public key must contain the shared element a");

        // Public key t must be in R_q (all coefficients < q)
        for &c in pk.t.coefficients() {
            assert!(c < Q, "public key coefficient must be < q");
        }
    }

    #[test]
    fn test_multiple_keys_same_a() {
        let ctx = ring_context();
        let mut rng = rand::rng();
        let a = generate_shared_a(ctx, &mut rng);

        let (_, pk1) = keygen(ctx, &a, &mut rng);
        let (_, pk2) = keygen(ctx, &a, &mut rng);

        assert_eq!(pk1.a, pk2.a, "all ring members must share the same a");
        // But their individual public keys t_i should differ (with overwhelming probability)
        assert_ne!(pk1.t, pk2.t, "distinct members should have distinct public keys");
    }
}
