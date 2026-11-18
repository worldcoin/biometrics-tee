use crate::{State, enrollment};
use rand::{Rng, RngCore, rngs::OsRng, seq::SliceRandom};
use selfie_enrollment_api_types::{POSEGUARD_CHALLENGE_COUNT, POSEGUARD_CHALLENGE_TTL_SECS};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{
    GeneratePoseGuardTargetsRequest, PoseGuardChallenge, PoseGuardTarget, PoseGuardTargetsResult,
};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

impl State {
    pub(crate) fn generate_poseguard_targets(
        &self,
        request: &GeneratePoseGuardTargetsRequest,
    ) -> Result<PoseGuardTargetsResult, Error> {
        request.validate().map_err(|_| Error::InvalidMessage)?;
        let producer = self.enrollment.as_ref().ok_or(Error::Unavailable)?;
        let challenge = self.challenges.issue()?;
        let attestation = challenge
            .attestation_nonce(request, &self.channel.public_key_commitment())
            .map_err(|_| Error::Unavailable)
            .and_then(|nonce| producer.attest_challenge(&nonce));
        match attestation {
            Ok(attestation) => Ok(PoseGuardTargetsResult {
                challenge,
                attestation,
            }),
            Err(error) => {
                self.challenges
                    .0
                    .lock()
                    .map_err(|_| Error::Unavailable)?
                    .remove(&challenge.challenge_token);
                Err(error)
            }
        }
    }
}

const MAX_PENDING_CHALLENGES: usize = 32;

#[derive(Default)]
pub(crate) struct Challenges(Mutex<HashMap<[u8; 32], PendingChallenge>>);

struct PendingChallenge {
    targets: [PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT],
    deadline: Instant,
}

impl Challenges {
    fn issue(&self) -> Result<PoseGuardChallenge, Error> {
        let mut pending = self.0.lock().map_err(|_| Error::Unavailable)?;
        let now = Instant::now();
        pending.retain(|_, entry| entry.deadline > now);
        if pending.len() >= MAX_PENDING_CHALLENGES {
            return Err(Error::Busy);
        }
        let mut challenge_token = [0; 32];
        OsRng
            .try_fill_bytes(&mut challenge_token)
            .map_err(|_| Error::Unavailable)?;
        if challenge_token == [0; 32] || pending.contains_key(&challenge_token) {
            return Err(Error::Unavailable);
        }
        let challenge = PoseGuardChallenge {
            challenge_token,
            targets: generate_targets(&mut OsRng),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Unavailable)?
                .as_secs()
                + POSEGUARD_CHALLENGE_TTL_SECS,
        };
        pending.insert(
            challenge_token,
            PendingChallenge {
                targets: challenge.targets,
                deadline: now + Duration::from_secs(POSEGUARD_CHALLENGE_TTL_SECS),
            },
        );
        Ok(challenge)
    }

    /// Removes a live challenge and returns its targets; each token redeems at most once.
    pub(crate) fn consume(
        &self,
        token: &[u8; 32],
    ) -> Result<[PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT], enrollment::Error> {
        let mut pending = self.0.lock().map_err(|_| enrollment::Error::Unavailable)?;
        match pending.remove(token) {
            Some(entry) if entry.deadline > Instant::now() => Ok(entry.targets),
            _ => Err(enrollment::Error::InvalidRequest),
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        &self,
        targets: [PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT],
    ) -> [u8; 32] {
        let token = rand::random();
        self.0.lock().unwrap().insert(
            token,
            PendingChallenge {
                targets,
                deadline: Instant::now() + Duration::from_secs(POSEGUARD_CHALLENGE_TTL_SECS),
            },
        );
        token
    }
}

fn generate_targets(rng: &mut (impl Rng + rand::CryptoRng)) -> [PoseGuardTarget; 3] {
    // Separate acceptance regions under the worker's 10-degree tolerance.
    let mut targets = [
        PoseGuardTarget {
            target_pitch: 0.0,
            target_yaw: -rng.gen_range(25..=35) as f32,
        },
        PoseGuardTarget {
            target_pitch: 0.0,
            target_yaw: rng.gen_range(25..=35) as f32,
        },
        PoseGuardTarget {
            target_pitch: rng.gen_range(15..=20) as f32
                * if rng.gen_bool(0.5) { 1.0 } else { -1.0 },
            target_yaw: 0.0,
        },
    ];
    targets.shuffle(rng);
    targets
}

#[cfg(test)]
mod tests;
