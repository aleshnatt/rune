//! Sequential challenge chain hashing.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::keys::PublicKey;
use crate::math::{poly_reduce_mod_q, zero_poly, Poly};
use crate::params::Params;

const DOMAIN_SEPARATOR: &[u8] = b"Rune-CHAIN-v2";

pub(crate) fn hash_chain(
    message: &[u8],
    ring: &[PublicKey],
    index: usize,
    w: &Poly,
    params: &Params,
) -> [u8; 64] {
    debug_assert_eq!(w.len(), params.n());
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(
        &u64::try_from(message.len())
            .expect("message length fits in u64")
            .to_le_bytes(),
    );
    hasher.update(message);
    hasher.update(
        &u64::try_from(ring.len())
            .expect("ring length fits in u64")
            .to_le_bytes(),
    );

    for pk in ring {
        for coeff in pk.t.coefficients() {
            hasher.update(&coeff.to_le_bytes());
        }
    }

    hasher.update(
        &u64::try_from(index)
            .expect("index fits in u64")
            .to_le_bytes(),
    );

    for coeff in w.coefficients() {
        hasher.update(&coeff.to_le_bytes());
    }

    let mut reader = hasher.finalize_xof();
    let mut out = [0_u8; 64];
    reader.read(&mut out);
    out
}

pub(crate) fn sample_challenge(seed: &[u8; 64], params: &Params) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = zero_poly(params);
    let mut occupied = vec![false; params.n()];
    let mut placed = 0_usize;

    while placed < params.kappa() {
        let mut pos_bytes = [0_u8; 2];
        reader.read(&mut pos_bytes);
        let pos = usize::from(u16::from_le_bytes(pos_bytes));

        // Rejection here avoids modulo bias in challenge positions.
        if pos >= params.n() || occupied[pos] {
            continue;
        }

        let mut sign_byte = [0_u8; 1];
        reader.read(&mut sign_byte);
        out.coefficients_mut()[pos] = if sign_byte[0] & 1 == 0 { 1 } else { -1 };
        occupied[pos] = true;
        placed += 1;
    }

    out
}

pub(crate) fn validate_challenge(c: &Poly, params: &Params) -> bool {
    if c.len() != params.n() {
        return false;
    }

    let mut nonzero = 0_usize;
    for coeff in c.coefficients() {
        match *coeff {
            0 => {}
            1 | -1 => nonzero += 1,
            _ => return false,
        }
    }

    nonzero == params.kappa()
}

pub(crate) fn normalize_challenge(c: &Poly, params: &Params) -> Poly {
    Poly(
        c.coefficients()
            .iter()
            .map(|coeff| poly_reduce_mod_q(i128::from(*coeff), params.q()))
            .collect(),
    )
}
