use super::*;
use biometric_engines_protocol::face::FaceImage;
use crypto_box::SecretKey;
use pontifex::{ChannelConsumer, ChannelDomain};
use rand::{SeedableRng, rngs::StdRng};
use selfie_enrollment_api_types::{CHANNEL_DOMAIN, ENROLLMENT_PROTOCOL_VERSION};
use selfie_enrollment_enclave_types::ExtractRequest;
use selfie_enrollment_identity::{
    AttestationFailed, CaptureAttestor, NONCE_BYTES, USER_DATA_BYTES,
};
use selfie_enrollment_sealed_types::{
    EnrollmentOperation, EnrollmentResult, FaceEmbedding, Failure, PoseGuardEnrollmentRequest,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn issued_challenge_is_bound_and_consumed_before_inference_on_the_same_channel() {
    let calls = Arc::new(AtomicUsize::new(0));
    let state = configured_state(calls.clone());
    let generation = generation();
    let assignment = state.assignment().await.unwrap();
    let channel = ChannelConsumer::from_unverified_public_key(
        ChannelDomain::new(CHANNEL_DOMAIN),
        &assignment.public_key,
    )
    .unwrap();
    let (ciphertext, opener) = channel
        .seal_to_enclave(&generation.encode().unwrap())
        .unwrap();
    let response = state.extract(ExtractRequest { ciphertext }).await.unwrap();
    assert!(response.await_capture);
    assert_eq!(state.processing.available_permits(), 1);
    let result =
        PoseGuardTargetsResult::decode(&opener.open_from_enclave(&response.ciphertext).unwrap())
            .unwrap();
    assert_eq!(
        result.attestation,
        result
            .challenge
            .attestation_nonce(&generation, &state.channel.public_key_commitment())
            .unwrap()
    );
    let mut enrollment = PoseGuardEnrollmentRequest {
        version: ENROLLMENT_PROTOCOL_VERSION,
        operation: EnrollmentOperation::EnrollWithPoseGuard,
        central_png: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
        captures: captures(&result.challenge),
        sub: generation.sub.clone(),
        custody_public_key: generation.custody_public_key.clone(),
        challenge_token: result.challenge.challenge_token,
    };
    for mutation in 0..5 {
        match mutation {
            0 => enrollment.sub = "0x20".into(),
            1 => {
                enrollment.custody_public_key = SecretKey::generate(&mut OsRng)
                    .public_key()
                    .as_bytes()
                    .to_vec()
            }
            2 => enrollment.captures.swap(0, 1),
            3 => enrollment.challenge_token = [9; 32],
            _ => {
                enrollment.captures[0].target_pitch *= -1.0;
                enrollment.captures[0].target_yaw *= -1.0;
            }
        }
        assert!(matches!(
            submit(&state, &channel, &enrollment).await,
            EnrollmentResult::Failed {
                reason: Failure::InvalidRequest
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        enrollment.sub.clone_from(&generation.sub);
        enrollment
            .custody_public_key
            .clone_from(&generation.custody_public_key);
        enrollment.captures = captures(&result.challenge);
        enrollment.challenge_token = result.challenge.challenge_token;
    }
    assert!(matches!(
        submit(&state, &channel, &enrollment).await,
        EnrollmentResult::Failed {
            reason: Failure::QualityRejected
        }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        submit(&state, &channel, &enrollment).await,
        EnrollmentResult::Failed {
            reason: Failure::InvalidRequest
        }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn expiry_reclaims_bounded_capacity_and_expired_tokens_never_run() {
    let challenges = Challenges::default();
    let request = generation();
    let first = challenges.issue(&request).unwrap();
    for _ in 1..MAX_PENDING_CHALLENGES {
        challenges.issue(&request).unwrap();
    }
    assert!(matches!(challenges.issue(&request), Err(Error::Busy)));
    tokio::time::advance(Duration::from_secs(POSEGUARD_CHALLENGE_TTL_SECS)).await;
    let key: [u8; 32] = request.custody_public_key.as_slice().try_into().unwrap();
    assert!(
        challenges
            .consume(
                &first.challenge_token,
                &request.sub,
                &key,
                &captures(&first)
            )
            .is_err()
    );
    challenges.issue(&request).unwrap();
    assert_eq!(challenges.0.lock().unwrap().len(), 1);
}

#[test]
fn simultaneous_replay_consumes_exactly_once() {
    let challenges = Arc::new(Challenges::default());
    let request = generation();
    let issued = challenges.issue(&request).unwrap();
    let key: [u8; 32] = request.custody_public_key.as_slice().try_into().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let challenges = challenges.clone();
            let issued = issued.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                challenges
                    .consume(&issued.challenge_token, "0x1f", &key, &captures(&issued))
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn target_policy_stays_in_worker_bounds_with_separate_acceptance_regions() {
    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..1000 {
        let targets = generate_targets(&mut rng);
        for (i, target) in targets.iter().enumerate() {
            assert!(target.target_pitch.abs() <= 20.0 && target.target_yaw.abs() <= 35.0);
            assert!(target.target_pitch.abs() > 10.0 || target.target_yaw.abs() > 10.0);
            for other in &targets[..i] {
                assert!(
                    (target.target_pitch - other.target_pitch).abs() > 20.0
                        || (target.target_yaw - other.target_yaw).abs() > 20.0
                );
            }
        }
    }
}

#[tokio::test]
async fn expired_challenge_cannot_bypass_the_direct_enrollment_entry_point() {
    let calls = Arc::new(AtomicUsize::new(0));
    let state = configured_state(calls.clone());
    let request = generation();
    let result = state.generate_poseguard_targets(&request).unwrap();
    state
        .challenges
        .0
        .lock()
        .unwrap()
        .get_mut(&result.challenge.challenge_token)
        .unwrap()
        .deadline = Instant::now();
    let key = PublicKey::from(<[u8; 32]>::try_from(request.custody_public_key.as_slice()).unwrap());
    // prepare_enrollment accepts explicit trusted context; it must still require a live challenge.
    let context = context();
    assert!(matches!(
        state.prepare_enrollment(
            enrollment::CaptureRequest {
                image_png: b"\x89PNG\r\n\x1a\nfixture",
                captures: &captures(&result.challenge),
                sub: &request.sub,
                custody_key: &key,
                challenge_token: result.challenge.challenge_token,
            },
            &context,
            &Attestor
        ),
        Err(enrollment::Error::InvalidRequest)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

async fn submit(
    state: &Arc<State>,
    channel: &ChannelConsumer,
    request: &PoseGuardEnrollmentRequest,
) -> EnrollmentResult {
    let (ciphertext, opener) = channel.seal_to_enclave(&request.encode().unwrap()).unwrap();
    let response = state.extract(ExtractRequest { ciphertext }).await.unwrap();
    assert!(!response.await_capture);
    EnrollmentResult::decode(&opener.open_from_enclave(&response.ciphertext).unwrap()).unwrap()
}

fn captures(challenge: &PoseGuardChallenge) -> [PoseGuardCapture; 3] {
    std::array::from_fn(|i| PoseGuardCapture {
        image: vec![i as u8 + 1],
        target_pitch: challenge.targets[i].target_pitch,
        target_yaw: challenge.targets[i].target_yaw,
    })
}

fn generation() -> GeneratePoseGuardTargetsRequest {
    GeneratePoseGuardTargetsRequest {
        version: ENROLLMENT_PROTOCOL_VERSION,
        operation: EnrollmentOperation::GeneratePoseGuardTargets,
        sub: "0x1f".into(),
        custody_public_key: SecretKey::generate(&mut OsRng)
            .public_key()
            .as_bytes()
            .to_vec(),
        nonce: [7; 32],
    }
}

fn context() -> enrollment::TrustedContext {
    enrollment::TrustedContext::new(
        std::array::from_fn(|_| SecretKey::generate(&mut OsRng).public_key()),
        [5; 48],
    )
    .unwrap()
}

fn configured_state(calls: Arc<AtomicUsize>) -> Arc<State> {
    Arc::new(
        State::new(Arc::new(Attestor), Box::new(Engine(calls)))
            .unwrap()
            .with_enrollment(enrollment::Producer::new(context(), Arc::new(Attestor))),
    )
}

struct Attestor;
impl crate::attestation::Attestor for Attestor {
    fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(key.to_vec())
    }
}
impl CaptureAttestor for Attestor {
    fn attest(
        &self,
        nonce: &[u8; NONCE_BYTES],
        _: &[u8; USER_DATA_BYTES],
    ) -> Result<Vec<u8>, AttestationFailed> {
        Ok(nonce.to_vec())
    }
}
struct Engine(Arc<AtomicUsize>);
impl crate::engine::Engine for Engine {
    fn extract(&self, _: &FaceImage) -> Result<Result<FaceEmbedding, Failure>, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Err(Failure::QualityRejected))
    }
    fn check_health(&self) -> Result<(), Error> {
        Ok(())
    }
}
