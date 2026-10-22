//! Nonce ownership for the draft challenge contract. Not exposed by the RPC router.
//!
//! Run creation/authorization, expiry, randomness verification, signing and reveal
//! gating are subsequent work. This helper must only receive enclave-owned context.
use rand::{RngCore, rngs::OsRng};
use selfie_enrollment_sealed_types::challenge::{self, ChallengeContext, TargetResponses};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Contract(#[from] challenge::Error),
    #[error("challenge randomness unavailable")]
    Entropy,
}

/// Owns one nonce without serialization, cloning, Debug output or a reveal API.
/// The nonce's owned buffer is zeroized on drop.
pub struct PreparedChallenge {
    context: ChallengeContext,
    nonce: Zeroizing<[u8; 32]>,
    commitment: [u8; 32],
}

impl PreparedChallenge {
    /// The future run controller assigns a unique ID and authenticated binding.
    /// Production startup already verifies the OS RNG is backed by `nsm-hwrng`.
    pub fn generate(context: ChallengeContext) -> Result<Self, Error> {
        context.validate()?;
        let mut nonce = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(nonce.as_mut())
            .map_err(|_| Error::Entropy)?;
        let commitment = challenge::commitment(&context, &nonce)?;
        Ok(Self {
            context,
            nonce,
            commitment,
        })
    }

    pub fn context(&self) -> &ChallengeContext {
        &self.context
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Pure derivation, not instruction issuance. The future controller must admit
    /// exactly one verified value for the committed source/round before calling it.
    pub fn target_responses(
        &self,
        external_randomness: &[u8; 32],
    ) -> Result<TargetResponses, Error> {
        Ok(challenge::derive_target_responses(
            &self.context,
            &self.nonce,
            external_randomness,
        )?)
    }
}
