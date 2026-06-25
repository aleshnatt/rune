//! Cryptographic parameter sets for Rune.

use crate::math::MAX_N;

/// System parameters for the Rune ring signature scheme.
///
/// Construct via the provided constants [`RUNE_128`] or [`RUNE_256`].
/// Custom parameter construction is intentionally not exposed: incorrect
/// choices can silently reduce security or cause signing to fail. Both
/// provided sets have been derived following the methodology of Ducas et al.
/// (CRYSTALS-Dilithium, IACR TCHES 2018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    n: usize,
    q: i64,
    eta: u8,
    kappa: usize,
    gamma: i64,
    beta: i64,
    omega: usize,
    max_attempts: usize,
}

impl Params {
    /// Creates a validated parameter set.
    ///
    /// # Panics
    ///
    /// Panics if the parameters are internally inconsistent.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        n: usize,
        q: i64,
        eta: u8,
        kappa: usize,
        gamma: i64,
        beta: i64,
        omega: usize,
        max_attempts: usize,
    ) -> Self {
        assert!(n > 0 && n <= MAX_N);
        assert!(q > 2 && q % 2 == 1);
        assert!(eta > 0);
        assert!(kappa > 0 && kappa < n);
        assert!(gamma > 0);
        assert!(beta > 0 && beta < gamma);
        assert!(omega > 0);
        assert!(max_attempts > 0);

        Self {
            n,
            q,
            eta,
            kappa,
            gamma,
            beta,
            omega,
            max_attempts,
        }
    }

    /// Polynomial degree.
    #[must_use]
    pub const fn n(&self) -> usize {
        self.n
    }

    /// Coefficient modulus.
    #[must_use]
    pub const fn q(&self) -> i64 {
        self.q
    }

    /// Centered binomial sampling parameter.
    #[must_use]
    pub const fn eta(&self) -> u8 {
        self.eta
    }

    /// Challenge Hamming weight.
    #[must_use]
    pub const fn kappa(&self) -> usize {
        self.kappa
    }

    /// Masking range.
    #[must_use]
    pub const fn gamma(&self) -> i64 {
        self.gamma
    }

    /// Rejection margin.
    #[must_use]
    pub const fn beta(&self) -> i64 {
        self.beta
    }

    /// Response norm bound used during rejection sampling.
    #[must_use]
    pub const fn response_bound(&self) -> i64 {
        self.gamma - self.beta
    }

    /// Maximum hint weight for parameter sets with hints.
    #[must_use]
    pub const fn omega(&self) -> usize {
        self.omega
    }

    /// Maximum signing attempt count.
    #[must_use]
    pub const fn max_attempts(&self) -> usize {
        self.max_attempts
    }
}

/// Demonstration parameters only. Security is approximately 10 bits. Use
/// `RUNE_256` for any real deployment.
pub const RUNE_128: Params = Params::new(256, 998_244_353, 2, 60, 249_561_088, 120, 60, 256);

/// NIST Category 1 target parameter set. Provides approximately 128 bits
/// of classical security. Suitable for production use pending independent
/// cryptographic audit. Uses q=8380417, which supports NTT-based polynomial
/// multiplication (q ≡ 1 mod 2n). The current implementation uses schoolbook
/// multiplication; NTT acceleration is planned for a future release.
pub const RUNE_256: Params = Params::new(512, 8_380_417, 3, 60, 524_288, 180, 120, 256);

#[cfg(test)]
mod param_tests {
    use super::*;

    #[test]
    fn params_constants_are_valid() {
        let _ = RUNE_128.n();
        let _ = RUNE_256.n();
    }
}
