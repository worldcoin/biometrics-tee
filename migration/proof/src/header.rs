//! Errors from validating and checking an ownership proof.

/// Bounds the sub forwarded to the verification service. Handlers' contract is
/// a 0x-prefixed hex string (66 bytes for a 32-byte value); 256 is generous
/// headroom that still stops a caller from relaying an arbitrarily large string.
pub const MAX_CREDENTIAL_SUB_BYTES: usize = 256;

/// Why proof verification failed. Display text is the response body and log tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofVerificationError {
    #[error("oversized")]
    Oversized,
    #[error("invalid")]
    Invalid,
    #[error("challenge_id_missing")]
    ChallengeIdMissing,
    #[error("proof_missing")]
    ProofMissing,
    #[error("credential_sub_missing")]
    CredentialSubMissing,
    #[error("verification_failed")]
    VerificationRejected,
    #[error("verification_error")]
    VerificationError,
}

impl ProofVerificationError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::Invalid => "invalid",
            Self::ChallengeIdMissing => "challenge_id_missing",
            Self::ProofMissing => "proof_missing",
            Self::CredentialSubMissing => "credential_sub_missing",
            Self::VerificationRejected => "verification_failed",
            Self::VerificationError => "verification_error",
        }
    }
}
