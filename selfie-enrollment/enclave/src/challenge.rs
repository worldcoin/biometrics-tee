//! Local generation helper; not yet connected to State, a run registry or an RPC.
use rand::{RngCore, rngs::OsRng};
use selfie_enrollment_sealed_types::challenge::{ChallengeTranscript, derive_target_options};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("challenge randomness unavailable")]
pub struct Error;

/// Generate a transcript containing an independent random ID and all three poses.
/// Production enclave startup checks `nsm-hwrng`; this also runs locally for development.
/// The seed is erased after derivation. RNG failure has no fallback.
///
/// This does not create an active run. A run registry must reject ID collisions,
/// bind ownership and track expiry and progress; the public ID is not a credential.
pub fn generate() -> Result<ChallengeTranscript, Error> {
    let mut challenge_id = [0; 16];
    OsRng.try_fill_bytes(&mut challenge_id).map_err(|_| Error)?;
    let mut seed = Zeroizing::new([0; 32]);
    let target_options = loop {
        OsRng.try_fill_bytes(seed.as_mut()).map_err(|_| Error)?;
        if let Some(options) = derive_target_options(&seed) {
            break options;
        }
    };
    Ok(ChallengeTranscript {
        challenge_id,
        target_options,
    })
}
