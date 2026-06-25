//! Error type for Rune operations.

/// Errors returned by Rune key, signing, and verification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuneError {
    /// Ring size is less than 2.
    RingTooSmall,
    /// Signer index is out of range for the given ring.
    SignerIndexOutOfRange,
    /// Not all public keys in the ring share the same public matrix seed.
    InconsistentRingParameter,
    /// A signature field has wrong length or structure.
    MalformedSignature,
    /// A supplied challenge polynomial has invalid weight or coefficients.
    MalformedChallenge,
    /// A public key has invalid structure.
    MalformedPublicKey,
    /// Rejection sampling did not terminate within the maximum number of attempts.
    RejectionSamplingFailed,
}

impl std::fmt::Display for RuneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RingTooSmall => f.write_str("ring size is less than 2"),
            Self::SignerIndexOutOfRange => f.write_str("signer index is out of range"),
            Self::InconsistentRingParameter => {
                f.write_str("public keys do not share the same ring parameter")
            }
            Self::MalformedSignature => f.write_str("signature has malformed structure"),
            Self::MalformedChallenge => f.write_str("challenge polynomial is malformed"),
            Self::MalformedPublicKey => f.write_str("public key has malformed structure"),
            Self::RejectionSamplingFailed => {
                f.write_str("rejection sampling failed within the attempt limit")
            }
        }
    }
}

impl std::error::Error for RuneError {}
