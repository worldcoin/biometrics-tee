//! Local generation helper; not yet connected to State, a run registry or an RPC.
use rand::{RngCore, rngs::OsRng};
use selfie_enrollment_sealed_types::challenge::{TargetResponses, derive_target_responses};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("challenge randomness unavailable")]
pub struct Error;

/// Keeps the expected responses enclave-side, without Debug or serialization.
/// The future run controller must store this value and issue only the current pose.
pub struct PreparedChallenge {
    challenge_id: [u8; 16],
    target_responses: TargetResponses,
}

impl PreparedChallenge {
    /// Generate an independent random ID and seed using the OS RNG. Production
    /// enclave startup checks `nsm-hwrng`; this helper also runs locally for development.
    /// The seed is erased after derivation. RNG failure has no fallback.
    ///
    /// A future registry must reject ID collisions, bind ownership, enforce expiry
    /// and track steps. The ID is public identification, not an ownership credential.
    pub fn generate() -> Result<Self, Error> {
        let mut challenge_id = [0; 16];
        OsRng.try_fill_bytes(&mut challenge_id).map_err(|_| Error)?;
        let mut seed = Zeroizing::new([0; 32]);
        let target_responses = loop {
            OsRng.try_fill_bytes(seed.as_mut()).map_err(|_| Error)?;
            if let Some(responses) = derive_target_responses(&seed) {
                break responses;
            }
        };
        Ok(Self {
            challenge_id,
            target_responses,
        })
    }

    pub fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }

    pub fn target_responses(&self) -> &TargetResponses {
        &self.target_responses
    }
}
