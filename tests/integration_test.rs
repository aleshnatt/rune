//! Integration tests for the Rune ring signature protocol.
//!
//! These tests exercise the full flow: key generation → signing → verification,
//! including negative tests for tampered messages and signatures.

use rune::core::{ring_sign, ring_verify};
use rune::keys::{generate_shared_a, keygen};
use rune::params::ring_context;

/// Helper: generate a ring of `size` members, returning (secret_keys, public_keys).
fn generate_ring(size: usize) -> (Vec<rune::keys::SecretKey>, Vec<rune::keys::PublicKey>) {
    let ctx = ring_context();
    let mut rng = rand::rng();
    let a = generate_shared_a(ctx, &mut rng);

    let mut sks = Vec::with_capacity(size);
    let mut pks = Vec::with_capacity(size);

    for _ in 0..size {
        let (sk, pk) = keygen(ctx, &a, &mut rng);
        sks.push(sk);
        pks.push(pk);
    }

    (sks, pks)
}

#[test]
fn test_full_flow_sign_and_verify() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(4);

    let msg = b"Rune blind relay: test message payload";
    let mut rng = rand::rng();

    // Signer at index 1 signs the message
    let sig = ring_sign(ctx, msg, &sks[1], 1, &pks, &mut rng)
        .expect("signing should succeed");

    // Verification should pass
    let valid = ring_verify(ctx, msg, &sig, &pks)
        .expect("verification should not error");
    assert!(valid, "valid signature must verify");
}

#[test]
fn test_different_signer_positions() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(4);
    let msg = b"testing different signer positions";
    let mut rng = rand::rng();

    // Each member should be able to sign and produce a valid signature
    for signer_idx in 0..4 {
        let sig = ring_sign(ctx, msg, &sks[signer_idx], signer_idx, &pks, &mut rng)
            .expect(&format!("signing at index {} should succeed", signer_idx));

        let valid = ring_verify(ctx, msg, &sig, &pks)
            .expect("verification should not error");
        assert!(
            valid,
            "signature from signer {} must verify",
            signer_idx
        );
    }
}

#[test]
fn test_wrong_message_fails_verification() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(3);
    let mut rng = rand::rng();

    let msg = b"original message";
    let sig = ring_sign(ctx, msg, &sks[0], 0, &pks, &mut rng)
        .expect("signing should succeed");

    // Verify with a different message — must fail
    let wrong_msg = b"tampered message";
    let valid = ring_verify(ctx, wrong_msg, &sig, &pks)
        .expect("verification should not error");
    assert!(!valid, "signature must not verify for a different message");
}

#[test]
fn test_modified_response_fails_verification() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(3);
    let mut rng = rand::rng();

    let msg = b"test modified response";
    let sig = ring_sign(ctx, msg, &sks[2], 2, &pks, &mut rng)
        .expect("signing should succeed");

    // Tamper with one response polynomial
    let mut tampered_sig = sig.clone();
    // Replace the first response with a zero element
    tampered_sig.responses_s[0] = ctx.zero_element();

    let valid = ring_verify(ctx, msg, &tampered_sig, &pks)
        .expect("verification should not error");
    assert!(!valid, "tampered signature must not verify");
}

#[test]
fn test_modified_challenge_fails_verification() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(3);
    let mut rng = rand::rng();

    let msg = b"test modified challenge";
    let sig = ring_sign(ctx, msg, &sks[1], 1, &pks, &mut rng)
        .expect("signing should succeed");

    // Tamper with one challenge polynomial
    let mut tampered_sig = sig.clone();
    tampered_sig.challenges[0] = ctx.zero_element();

    let valid = ring_verify(ctx, msg, &tampered_sig, &pks)
        .expect("verification should not error");
    assert!(!valid, "tampered challenge must cause verification failure");
}

#[test]
fn test_ring_of_two_members() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(2);
    let mut rng = rand::rng();

    let msg = b"minimal ring size test";
    let sig = ring_sign(ctx, msg, &sks[0], 0, &pks, &mut rng)
        .expect("signing with 2-member ring should succeed");

    let valid = ring_verify(ctx, msg, &sig, &pks)
        .expect("verification should not error");
    assert!(valid, "2-member ring signature must verify");
}

#[test]
fn test_signature_size_matches_ring() {
    let ctx = ring_context();
    let (sks, pks) = generate_ring(5);
    let mut rng = rand::rng();

    let msg = b"size check";
    let sig = ring_sign(ctx, msg, &sks[3], 3, &pks, &mut rng)
        .expect("signing should succeed");

    assert_eq!(sig.responses_s.len(), 5, "responses must match ring size");
    assert_eq!(sig.responses_e.len(), 5, "responses_e must match ring size");
    assert_eq!(sig.challenges.len(), 5, "challenges must match ring size");
}
