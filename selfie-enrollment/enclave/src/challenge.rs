//! Local generation helper; not yet connected to State, a run registry or an RPC.
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{RngCore, rngs::OsRng};
use selfie_enrollment_sealed_types::challenge::{ChallengeTranscript, derive_target_options};
use zeroize::Zeroizing;

/// Initial prototype lifetime, measured from generation.
pub const CHALLENGE_TTL_MS: u64 = 90_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("challenge randomness unavailable")]
    Randomness,
    #[error("challenge clock unavailable or out of range")]
    Clock,
}

/// Generate a transcript containing an independent random ID, all three poses and expiry.
/// Production enclave startup checks `nsm-hwrng`; this also runs locally for development.
/// The seed is erased after derivation. RNG failure has no fallback.
///
/// This does not create an active run. A run registry must reject ID collisions,
/// bind ownership and track progress; the public ID is not a credential. Expiry is
/// OS-clock metadata, not attested time. The registry must enforce elapsed lifetime
/// with a monotonic deadline and remove expired runs.
pub fn generate() -> Result<ChallengeTranscript, Error> {
    let generated_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_millis(),
    )
    .map_err(|_| Error::Clock)?;
    let expires_at_unix_ms = generated_at_unix_ms
        .checked_add(CHALLENGE_TTL_MS)
        .ok_or(Error::Clock)?;
    let mut challenge_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut challenge_id)
        .map_err(|_| Error::Randomness)?;
    let mut seed = Zeroizing::new([0; 32]);
    let target_options = loop {
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Randomness)?;
        if let Some(options) = derive_target_options(&seed) {
            break options;
        }
    };
    Ok(ChallengeTranscript {
        challenge_id,
        target_options,
        expires_at_unix_ms,
    })
}
