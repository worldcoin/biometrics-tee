//! Enclave-owned, one-use challenges gate the existing attested enrollment producer.
use crate::{
    State,
    enrollment::{CaptureRequest, Error as EnrollmentError},
};
use crypto_box::PublicKey;
use rand::{Rng, RngCore, rngs::OsRng, seq::SliceRandom};
use selfie_enrollment_api_types::POSEGUARD_SESSION_TTL_SECS;
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{
    EnrollmentBundle, EnrollmentField, EnrollmentResult, Failure,
    poseguard::{Action, Challenge, Outcome, PoseTarget, Reply, Request},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_SESSIONS: usize = 16;
const MAX_BEGINS: usize = 128;

#[derive(Default)]
pub(crate) struct Sessions {
    entries: HashMap<[u8; 32], Session>,
    // Replayed begin ciphertext must not issue another set of targets while the client waits.
    begins: HashMap<[u8; 32], Instant>,
}
struct Session {
    sub: Zeroizing<String>,
    custody_key: PublicKey,
    auth_key: Zeroizing<[u8; 32]>,
    targets: [PoseTarget; 3],
    expires: Instant,
}

impl State {
    pub(crate) fn enroll_poseguard(&self, request: &Request) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.enroll_poseguard_at(request, Instant::now())
    }

    fn enroll_poseguard_at(
        &self,
        request: &Request,
        now: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let producer = self.enrollment.as_ref().ok_or(Error::Unavailable)?;
        let (id, key, outcome) = match &request.action {
            Action::Begin {
                sub,
                custody_public_key,
                auth_key,
            } => {
                selfie_enrollment_identity::validate_sub(sub).map_err(|_| Error::InvalidMessage)?;
                let custody_key = PublicKey::from(*custody_public_key);
                embedding_shares::validate_recipients(std::slice::from_ref(&custody_key))
                    .map_err(|_| Error::InvalidMessage)?;
                let mut sessions = self.poseguard.lock().map_err(|_| Error::Unavailable)?;
                sessions.entries.retain(|_, session| now < session.expires);
                sessions.begins.retain(|_, expires| now < *expires);
                if sessions.begins.contains_key(&request.nonce) {
                    return Err(Error::InvalidMessage);
                }
                if sessions.entries.len() >= MAX_SESSIONS || sessions.begins.len() >= MAX_BEGINS {
                    return Err(Error::Busy);
                }
                let id = random_id()?;
                if sessions.entries.contains_key(&id) {
                    return Err(Error::Unavailable);
                }
                let targets = generate_targets();
                let expires = now + Duration::from_secs(POSEGUARD_SESSION_TTL_SECS);
                sessions.begins.insert(request.nonce, expires);
                sessions.entries.insert(
                    id,
                    Session {
                        sub: Zeroizing::new(sub.clone()),
                        custody_key,
                        auth_key: Zeroizing::new(*auth_key),
                        targets,
                        expires,
                    },
                );
                (
                    id,
                    Zeroizing::new(*auth_key),
                    Outcome::Challenge {
                        challenge: Challenge {
                            session_id: id,
                            targets,
                            expires_in_ms: POSEGUARD_SESSION_TTL_SECS * 1000,
                        },
                    },
                )
            }
            Action::Submit {
                session_id,
                capture,
            } => {
                capture.validate().map_err(|_| Error::InvalidMessage)?;
                let session = self.take_poseguard_session(session_id, now)?;
                let input = CaptureRequest {
                    image_png: &capture.central_png,
                    challenges: std::array::from_fn(|i| {
                        (capture.challenges[i].0.as_slice(), session.targets[i])
                    }),
                    sub: &session.sub,
                    custody_key: &session.custody_key,
                };
                let result =
                    match self.produce(&input, &producer.context, producer.attestor.as_ref()) {
                        Ok(prepared) => {
                            let fields = prepared
                                .form
                                .parts()
                                .into_iter()
                                .map(|(name, value)| {
                                    std::str::from_utf8(value).map(|value| EnrollmentField {
                                        name: name.to_owned(),
                                        value: value.to_owned(),
                                    })
                                })
                                .collect::<Result<_, _>>()
                                .map_err(|_| Error::Unavailable)?;
                            EnrollmentResult::Success {
                                enrollment: EnrollmentBundle {
                                    fields,
                                    attestation_header: prepared.attestation_header,
                                    encrypted_custody: prepared.encrypted_custody,
                                },
                            }
                        }
                        Err(EnrollmentError::Capture(reason)) => {
                            EnrollmentResult::Failed { reason }
                        }
                        Err(EnrollmentError::InvalidRequest) => EnrollmentResult::Failed {
                            reason: Failure::InvalidRequest,
                        },
                        Err(EnrollmentError::Busy | EnrollmentError::Unavailable) => {
                            return Err(Error::Unavailable);
                        }
                    };
                (
                    *session_id,
                    session.auth_key,
                    Outcome::Enrollment { result },
                )
            }
            Action::Cancel { session_id } => {
                let session = self.take_poseguard_session(session_id, now)?;
                (*session_id, session.auth_key, Outcome::Cancelled)
            }
        };
        Reply {
            nonce: request.nonce,
            session_id: id,
            outcome,
        }
        .encode_authenticated(&key)
        .map_err(|_| Error::Unavailable)
    }

    fn take_poseguard_session(&self, id: &[u8; 32], now: Instant) -> Result<Session, Error> {
        let session = self
            .poseguard
            .lock()
            .map_err(|_| Error::Unavailable)?
            .entries
            .remove(id)
            .ok_or(Error::InvalidMessage)?;
        if now >= session.expires {
            return Err(Error::Timeout);
        }
        Ok(session)
    }
}

fn random_id() -> Result<[u8; 32], Error> {
    let mut id = [0; 32];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| Error::Unavailable)?;
    if id == [0; 32] {
        return Err(Error::Unavailable);
    }
    Ok(id)
}

fn generate_targets() -> [PoseTarget; 3] {
    let mut quadrants = [(1, 1), (-1, 1), (1, -1), (-1, -1)];
    quadrants.shuffle(&mut OsRng);
    // Three distinct quadrants have disjoint ten-degree tolerance windows. Yaw also
    // separates every challenge from the neutral pose; the jitter stays in worker bounds.
    std::array::from_fn(|i| PoseTarget {
        pitch: quadrants[i].0 * OsRng.gen_range(12..=20),
        yaw: quadrants[i].1 * OsRng.gen_range(23..=35),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestation::Attestor,
        engine::Engine,
        enrollment::{Producer, TrustedContext},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use biometric_engines_protocol::face::{FaceImage, face_image::Source};
    use crypto_box::SecretKey;
    use selfie_enrollment_identity::{
        AttestationFailed, CaptureAttestor, NONCE_BYTES, USER_DATA_BYTES,
    };
    use selfie_enrollment_sealed_types::{
        ChallengeFailure, FaceEmbedding,
        poseguard::{CaptureBatch, ChallengeImage, VERSION},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct TestAttestor(AtomicUsize);
    impl Attestor for TestAttestor {
        fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(key.to_vec())
        }
    }
    impl CaptureAttestor for TestAttestor {
        fn attest(
            &self,
            _: &[u8; NONCE_BYTES],
            _: &[u8; USER_DATA_BYTES],
        ) -> Result<Vec<u8>, AttestationFailed> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(b"attested-capture".to_vec())
        }
    }
    struct TestEngine {
        failure: Option<Failure>,
        calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<(f32, f32)>>>,
    }
    impl Engine for TestEngine {
        fn extract(&self, image: &FaceImage) -> Result<Result<FaceEmbedding, Failure>, Error> {
            let Some(Source::PoseGuard(capture)) = &image.source else {
                panic!("PoseGuard is mandatory for enrollment");
            };
            assert_eq!(capture.central_image, b"\x89PNG\r\n\x1a\ncentral");
            assert_eq!(capture.challenges.len(), 3);
            for (i, frame) in capture.challenges.iter().enumerate() {
                assert_eq!(frame.image, vec![i as u8 + 1]);
            }
            *self.targets.lock().unwrap() = capture
                .challenges
                .iter()
                .map(|c| (c.target_pitch, c.target_yaw))
                .collect();
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(failure) = self.failure {
                return Ok(Err(failure));
            }
            let mut vector = 512_u64.to_le_bytes().to_vec();
            vector.resize(8 + 512 * 4, 0);
            Ok(Ok(FaceEmbedding {
                embedding: STANDARD.encode(vector),
                embedding_type: "ghostfacenet_flipped_mean".into(),
                embedding_version: "2.0.0".into(),
                embedding_inference_backend: "face-engine".into(),
            }))
        }
        fn check_health(&self) -> Result<(), Error> {
            Ok(())
        }
    }
    struct Harness {
        state: State,
        attestor: Arc<TestAttestor>,
        calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<(f32, f32)>>>,
    }
    impl Harness {
        fn new(failure: Option<Failure>) -> Self {
            let calls = Arc::new(AtomicUsize::new(0));
            let targets = Arc::new(Mutex::new(Vec::new()));
            let attestor = Arc::new(TestAttestor(AtomicUsize::new(0)));
            let context = TrustedContext::new(
                std::array::from_fn(|_| SecretKey::generate(&mut OsRng).public_key()),
                [1; 48],
            )
            .unwrap();
            let state = State::new(
                attestor.clone(),
                Box::new(TestEngine {
                    failure,
                    calls: calls.clone(),
                    targets: targets.clone(),
                }),
            )
            .unwrap()
            .with_enrollment(Producer::new(context, attestor.clone()));
            Self {
                state,
                attestor,
                calls,
                targets,
            }
        }
        fn call(&self, request: &Request, now: Instant) -> Result<Reply, Error> {
            let encoded = self.state.enroll_poseguard_at(request, now)?;
            Ok(Reply::decode_authenticated(&encoded, &[9; 32], &request.nonce).unwrap())
        }
    }
    fn begin(nonce: u8) -> Request {
        Request {
            version: VERSION,
            nonce: [nonce; 32],
            action: Action::Begin {
                sub: "0x1f".into(),
                custody_public_key: *SecretKey::from([8; 32]).public_key().as_bytes(),
                auth_key: [9; 32],
            },
        }
    }
    fn submit(id: [u8; 32]) -> Request {
        Request {
            version: VERSION,
            nonce: [2; 32],
            action: Action::Submit {
                session_id: id,
                capture: CaptureBatch {
                    central_png: b"\x89PNG\r\n\x1a\ncentral".to_vec(),
                    challenges: std::array::from_fn(|i| ChallengeImage(vec![i as u8 + 1])),
                },
            },
        }
    }
    #[test]
    fn issued_targets_drive_one_batch_and_bind_the_enrollment_subject_and_custody_key() {
        let h = Harness::new(None);
        let now = Instant::now();
        let first = h.call(&begin(1), now).unwrap();
        assert_eq!(h.calls.load(Ordering::SeqCst), 0);
        assert!(h.state.processing.try_acquire().is_ok());
        let Outcome::Challenge { challenge } = &first.outcome else {
            panic!("expected challenge")
        };
        let response = h.call(&submit(first.session_id), now).unwrap();
        let Outcome::Enrollment {
            result: EnrollmentResult::Success { enrollment },
        } = &response.outcome
        else {
            panic!("expected enrollment")
        };
        assert_eq!(
            *h.targets.lock().unwrap(),
            challenge
                .targets
                .map(|t| (f32::from(t.pitch), f32::from(t.yaw)))
        );
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        assert_eq!(h.attestor.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            enrollment
                .fields
                .iter()
                .find(|f| f.name == "sub")
                .unwrap()
                .value,
            "0x1f"
        );
        assert!(
            SecretKey::from([8; 32])
                .unseal(&enrollment.encrypted_custody)
                .is_ok()
        );
        assert!(
            SecretKey::from([7; 32])
                .unseal(&enrollment.encrypted_custody)
                .is_err()
        );
        assert!(h.call(&submit(first.session_id), now).is_err());
        assert!(h.call(&begin(1), now).is_err());
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn any_challenge_rejection_prevents_attestation_and_consumes_the_attempt() {
        for index in 0..3 {
            for reason in [
                ChallengeFailure::PoseMismatch,
                ChallengeFailure::IdentityMismatch,
            ] {
                let failure = Failure::Challenge { index, reason };
                let h = Harness::new(Some(failure));
                let now = Instant::now();
                let first = h.call(&begin(1), now).unwrap();
                let response = h.call(&submit(first.session_id), now).unwrap();
                assert!(
                    matches!(response.outcome, Outcome::Enrollment { result: EnrollmentResult::Failed { reason } } if reason == failure)
                );
                assert_eq!(h.attestor.0.load(Ordering::SeqCst), 0);
                assert!(h.call(&submit(first.session_id), now).is_err());
                assert_eq!(h.calls.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn expired_cancelled_unknown_and_other_boot_sessions_never_reach_worker() {
        let h = Harness::new(None);
        let other = Harness::new(None);
        let now = Instant::now();
        let first = h.call(&begin(1), now).unwrap();
        assert!(other.call(&submit(first.session_id), now).is_err());
        assert!(h.call(&submit([7; 32]), now).is_err());
        assert!(matches!(
            h.call(
                &submit(first.session_id),
                now + Duration::from_secs(POSEGUARD_SESSION_TTL_SECS)
            ),
            Err(Error::Timeout)
        ));
        let first = h.call(&begin(2), now).unwrap();
        let cancel = Request {
            version: VERSION,
            nonce: [3; 32],
            action: Action::Cancel {
                session_id: first.session_id,
            },
        };
        assert!(matches!(
            h.call(&cancel, now).unwrap().outcome,
            Outcome::Cancelled
        ));
        assert!(h.call(&submit(first.session_id), now).is_err());
        assert_eq!(h.calls.load(Ordering::SeqCst), 0);
        assert_eq!(h.attestor.0.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn begin_replay_capacity_and_expiry_are_bounded() {
        let h = Harness::new(None);
        let now = Instant::now();
        h.call(&begin(1), now).unwrap();
        assert!(h.call(&begin(1), now).is_err());
        for i in 2..=MAX_SESSIONS {
            h.call(&begin(i as u8), now).unwrap();
        }
        assert!(matches!(h.call(&begin(17), now), Err(Error::Busy)));
        h.call(
            &begin(17),
            now + Duration::from_secs(POSEGUARD_SESSION_TTL_SECS),
        )
        .unwrap();
        assert_eq!(h.state.poseguard.lock().unwrap().entries.len(), 1);
    }
    #[test]
    fn issued_targets_have_disjoint_acceptance_windows() {
        for _ in 0..1000 {
            let targets = generate_targets();
            for (i, target) in targets.iter().enumerate() {
                target.validate().unwrap();
                assert!(target.pitch.abs() > 20 || target.yaw.abs() > 20);
                for other in &targets[..i] {
                    assert!(
                        (target.pitch - other.pitch).abs() > 20
                            || (target.yaw - other.yaw).abs() > 20
                    );
                }
            }
        }
    }
}
