#![allow(clippy::similar_names)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::challenge::sample_challenge;
use crate::core::RingSignature;
use crate::math::{poly_infinity_norm, zero_poly, Poly};
use crate::{
    generate_shared_a, keygen, ring_sign, ring_verify, RuneError, SecretKey, RUNE_128, RUNE_256,
};

fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn make_ring(size: usize) -> (Vec<crate::PublicKey>, Vec<SecretKey>) {
    make_ring_with_seed(size, 7, &RUNE_128)
}

fn make_ring_with_seed(
    size: usize,
    seed: u64,
    params: &'static crate::Params,
) -> (Vec<crate::PublicKey>, Vec<SecretKey>) {
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(seed);
    let a = generate_shared_a(params, &mut rng);
    let mut pks = Vec::with_capacity(size);
    let mut sks = Vec::with_capacity(size);

    for _ in 0..size {
        // keygen only fails if `a` is malformed; this `a` is freshly generated.
        let (pk, sk) = keygen(&a, params, &mut rng).unwrap();
        pks.push(pk);
        sks.push(sk);
    }

    (pks, sks)
}

#[test]
fn test_sign_verify_k2() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(2);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(11);
    let sig = ring_sign(b"message", 0, &sks[0], &ring, params, &mut rng).unwrap();
    assert_eq!(ring_verify(b"message", &sig, &ring, params), Ok(true));
}

#[test]
fn test_sign_verify_k5_all_signers() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(5);

    for (signer, sk) in sks.iter().enumerate().take(5) {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = seeded_rng(u64::try_from(signer).unwrap() + 20);
        let sig = ring_sign(b"message", signer, sk, &ring, params, &mut rng).unwrap();
        assert_eq!(ring_verify(b"message", &sig, &ring, params), Ok(true));
    }
}

#[test]
fn test_sign_verify_rune256_k2() {
    let params = &RUNE_256;
    let (ring, sks) = make_ring_with_seed(2, 80, params);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(81);
    let sig = ring_sign(b"message", 0, &sks[0], &ring, params, &mut rng).unwrap();
    assert_eq!(ring_verify(b"message", &sig, &ring, params), Ok(true));
}

#[test]
fn test_rune256_rejection_sampling_terminates() {
    let params = &RUNE_256;
    let (ring, sks) = make_ring_with_seed(3, 82, params);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(83);
    let sig = ring_sign(b"message", 1, &sks[1], &ring, params, &mut rng)
        .expect("RUNE_256 should accept within the attempt limit");
    assert_eq!(ring_verify(b"message", &sig, &ring, params), Ok(true));
}

#[test]
fn test_readme_quick_start() -> Result<(), RuneError> {
    // This test mirrors the README Quick Start example exactly.
    // If this test fails, update the README.
    use rand::rngs::OsRng;

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

#[test]
fn test_wrong_message_rejected() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(31);
    let sig = ring_sign(b"m1", 1, &sks[1], &ring, params, &mut rng).unwrap();
    assert_eq!(ring_verify(b"m2", &sig, &ring, params), Ok(false));
}

#[test]
fn test_wrong_ring_rejected() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    let (wrong_ring, _) = make_ring_with_seed(3, 41, params);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(32);
    let sig = ring_sign(b"m", 1, &sks[1], &ring, params, &mut rng).unwrap();
    assert_eq!(ring_verify(b"m", &sig, &wrong_ring, params), Ok(false));
}

#[test]
fn test_modified_z_rejected() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(33);
    let mut sig = ring_sign(b"m", 2, &sks[2], &ring, params, &mut rng).unwrap();
    sig.z_s[0].coefficients_mut()[0] ^= 1;
    assert_eq!(ring_verify(b"m", &sig, &ring, params), Ok(false));
}

#[test]
fn test_modified_challenge_rejected() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(34);
    let mut sig = ring_sign(b"m", 2, &sks[2], &ring, params, &mut rng).unwrap();
    sig.c[0].coefficients_mut()[0] += 1;
    assert_eq!(ring_verify(b"m", &sig, &ring, params), Ok(false));
}

#[test]
fn test_malformed_signature_too_short() {
    let params = &RUNE_128;
    let (ring, _) = make_ring(3);
    let sig = RingSignature {
        z_s: vec![zero_poly(params); 2],
        z_e: vec![zero_poly(params); 3],
        c: vec![zero_poly(params); 3],
    };
    assert_eq!(
        ring_verify(b"m", &sig, &ring, params),
        Err(RuneError::MalformedSignature)
    );
}

#[test]
fn test_inconsistent_ring_a_rejected() {
    let params = &RUNE_128;
    let (mut ring, sks) = make_ring(3);
    let (other_ring, _) = make_ring_with_seed(3, 51, params);
    ring[1].a = other_ring[1].a.clone();
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(35);
    assert_eq!(
        ring_sign(b"m", 0, &sks[0], &ring, params, &mut rng),
        Err(RuneError::InconsistentRingParameter)
    );

    let sig = RingSignature {
        z_s: vec![zero_poly(params); 3],
        z_e: vec![zero_poly(params); 3],
        c: vec![zero_poly(params); 3],
    };
    assert_eq!(
        ring_verify(b"m", &sig, &ring, params),
        Err(RuneError::InconsistentRingParameter)
    );
}

#[test]
fn test_signer_index_out_of_range() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(36);
    assert_eq!(
        ring_sign(b"m", 3, &sks[0], &ring, params, &mut rng),
        Err(RuneError::SignerIndexOutOfRange)
    );
}

#[test]
fn test_ring_too_small() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(1);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(37);
    assert_eq!(
        ring_sign(b"m", 0, &sks[0], &ring, params, &mut rng),
        Err(RuneError::RingTooSmall)
    );
}

#[test]
fn test_secret_key_debug_redacted() {
    let (_, sks) = make_ring(2);
    let debug = format!("{:?}", sks[0]);
    assert!(debug.contains("[REDACTED]"));
    assert!(!contains_long_digit_sequence(&debug));
}

#[test]
fn test_challenge_weight() {
    let params = &RUNE_128;
    for i in 0..100_u64 {
        let mut seed = [0_u8; 64];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        let c = sample_challenge(&seed, params);
        let nonzero = c.coefficients().iter().filter(|coeff| **coeff != 0).count();
        assert_eq!(nonzero, params.kappa());
        assert!(c
            .coefficients()
            .iter()
            .all(|coeff| matches!(*coeff, -1..=1)));
    }
}

#[test]
fn test_poly_imin_does_not_panic() {
    let mut coeffs = vec![0; RUNE_128.n()];
    coeffs[0] = i64::MIN;
    let poly = Poly(coeffs);

    assert_eq!(poly_infinity_norm(&poly), i64::MAX);
    let _ = format!("{poly:?}");
}

#[test]
fn test_poly_from_coefficients_checked() {
    let params = &RUNE_128;
    let coeffs = vec![0; params.n()];
    let poly = Poly::from_coefficients(coeffs, params).unwrap();
    assert_eq!(poly.len(), params.n());
}

#[test]
fn test_poly_from_coefficients_rejects_malformed() {
    let params = &RUNE_128;

    assert_eq!(
        Poly::from_coefficients(vec![0; params.n() - 1], params),
        Err(RuneError::MalformedPublicKey)
    );

    let mut coeffs = vec![0; params.n()];
    coeffs[0] = i64::MIN;
    assert_eq!(
        Poly::from_coefficients(coeffs, params),
        Err(RuneError::MalformedPublicKey)
    );
}

#[test]
fn test_determinism() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng_a = seeded_rng(38);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng_b = seeded_rng(38);
    let sig_a = ring_sign(b"m", 1, &sks[1], &ring, params, &mut rng_a).unwrap();
    let sig_b = ring_sign(b"m", 1, &sks[1], &ring, params, &mut rng_b).unwrap();
    assert_eq!(sig_a, sig_b);
}

#[test]
fn test_cross_ring_size() {
    let params = &RUNE_128;
    let (ring, sks) = make_ring(3);
    let (wrong_ring, _) = make_ring_with_seed(4, 61, params);
    // Seeded for test determinism. Production code must use OsRng.
    let mut rng = seeded_rng(39);
    let sig = ring_sign(b"m", 1, &sks[1], &ring, params, &mut rng).unwrap();
    let result = ring_verify(b"m", &sig, &wrong_ring, params);
    assert!(matches!(
        result,
        Ok(false) | Err(RuneError::MalformedSignature)
    ));
}

fn contains_long_digit_sequence(s: &str) -> bool {
    let mut count = 0_usize;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            count += 1;
            if count > 3 {
                return true;
            }
        } else {
            count = 0;
        }
    }
    false
}
