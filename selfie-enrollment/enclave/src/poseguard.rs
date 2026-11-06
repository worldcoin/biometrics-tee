//! Shadow evaluation only. This state never grants or denies enrollment.
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use rand::{Rng, RngCore, rngs::OsRng};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{
    FaceEmbedding,
    poseguard::{
        Action, MAX_EXCHANGES, Outcome, PoseTarget, Rejection, Reply, Request, SESSION_TTL_SECS,
    },
};
use zeroize::Zeroizing;

use crate::{State, engine::PoseEvaluation};

const MAX_SESSIONS: usize = 16;
const CHALLENGES: u32 = 3;
const MAX_ATTEMPTS: u32 = 3;
const TARGET_TIMEOUT: Duration = Duration::from_secs(15);
const SIMILARITY_THRESHOLD: f64 = 0.4;

#[derive(Default)]
pub(crate) struct Sessions {
    entries: HashMap<[u8; 32], Session>,
}
impl Sessions {
    pub(crate) fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, session| now < session.expires);
    }
}
struct Session {
    key: Zeroizing<[u8; 32]>,
    next_sequence: u32,
    expires: Instant,
    deadline: Instant,
    identity: Option<FaceEmbedding>,
    target: Option<PoseTarget>,
    completed: u32,
    attempt: u32,
}
impl Session {
    fn capture(&self, retry: Option<Rejection>) -> Outcome {
        Outcome::Capture {
            target: self.target,
            challenge_index: self.completed,
            sequence_attempt: self.attempt,
            retry,
        }
    }
    fn failed(reason: Rejection) -> Outcome {
        Outcome::Complete {
            passed: false,
            reason: Some(reason),
        }
    }
    fn next_target(&mut self, now: Instant) -> Result<(), Error> {
        self.target = Some(generate_target(self.target)?);
        self.deadline = now + TARGET_TIMEOUT;
        Ok(())
    }
    fn timeout(&mut self, now: Instant) -> Result<Outcome, Error> {
        if self.identity.is_none() {
            return Ok(Self::failed(Rejection::Expired));
        }
        if self.attempt == MAX_ATTEMPTS {
            return Ok(Self::failed(Rejection::AttemptsExhausted));
        }
        self.attempt += 1;
        self.completed = 0;
        self.next_target(now)?;
        Ok(self.capture(None))
    }
}

fn generate_target(previous: Option<PoseTarget>) -> Result<PoseTarget, Error> {
    let previous = previous.unwrap_or(PoseTarget { pitch: 0, yaw: 0 });
    for _ in 0..500 {
        let target = PoseTarget {
            pitch: OsRng.gen_range(-20..=20),
            yaw: OsRng.gen_range(-35..=35),
        };
        let pitch = (target.pitch - previous.pitch).abs();
        let yaw = (target.yaw - previous.yaw).abs();
        // Tolerances are ten degrees on each axis, for both the old and new target.
        if pitch >= 10 && yaw >= 15 && (pitch > 20 || yaw > 20) {
            return Ok(target);
        }
    }
    Err(Error::Unavailable)
}

impl State {
    pub(crate) fn evaluate_poseguard(
        &self,
        request: &Request,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.evaluate_poseguard_at(request, Instant::now())
    }

    fn evaluate_poseguard_at(
        &self,
        request: &Request,
        now: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.engine.supports_poseguard() {
            return Err(Error::Unavailable);
        }
        let (id, session, outcome) = match &request.action {
            Action::Begin { auth_key } => {
                let mut sessions = self.poseguard.lock().map_err(|_| Error::Unavailable)?;
                sessions.expire(now);
                if sessions.entries.len() >= MAX_SESSIONS {
                    return Err(Error::Busy);
                }
                let mut id = [0; 32];
                OsRng
                    .try_fill_bytes(&mut id)
                    .map_err(|_| Error::Unavailable)?;
                if id == [0; 32] || sessions.entries.contains_key(&id) {
                    return Err(Error::Unavailable);
                }
                let session = Session {
                    key: Zeroizing::new(*auth_key),
                    next_sequence: 1,
                    expires: now + Duration::from_secs(SESSION_TTL_SECS),
                    deadline: now + Duration::from_secs(30),
                    identity: None,
                    target: None,
                    completed: 0,
                    attempt: 1,
                };
                let outcome = session.capture(None);
                (id, session, outcome)
            }
            Action::Submit {
                session_id,
                sequence,
                image,
            } => {
                let mut session = self.take_pose_session(session_id, *sequence)?;
                let outcome =
                    if now >= session.expires || session.next_sequence >= MAX_EXCHANGES - 1 {
                        Session::failed(Rejection::Expired)
                    } else if now >= session.deadline {
                        session.timeout(now)?
                    } else {
                        let inference_started = Instant::now();
                        let evaluation = self.engine.evaluate_pose(
                            image,
                            session.target,
                            session.identity.as_ref(),
                        )?;
                        // Preserve a caller-supplied test clock while accounting for time spent in inference.
                        let finished = now + inference_started.elapsed();
                        if finished >= session.expires {
                            Session::failed(Rejection::Expired)
                        } else if finished >= session.deadline {
                            session.timeout(finished)?
                        } else {
                            session.apply(evaluation, finished)?
                        }
                    };
                session.next_sequence += 1;
                (*session_id, session, outcome)
            }
            Action::Cancel {
                session_id,
                sequence,
            } => {
                let mut session = self.take_pose_session(session_id, *sequence)?;
                session.next_sequence += 1;
                (*session_id, session, Session::failed(Rejection::Cancelled))
            }
        };
        let terminal = matches!(outcome, Outcome::Complete { .. });
        if let Outcome::Complete { passed, reason } = &outcome {
            tracing::info!(operation = "poseguard_shadow", passed, reason = ?reason, "PoseGuard shadow evaluation completed");
        }
        let reply = Reply {
            nonce: request.nonce,
            session_id: id,
            next_sequence: session.next_sequence,
            outcome,
        };
        let encoded = reply
            .encode_authenticated(&session.key)
            .map_err(|_| Error::Unavailable)?;
        if !terminal {
            self.poseguard
                .lock()
                .map_err(|_| Error::Unavailable)?
                .entries
                .insert(id, session);
        }
        Ok(encoded)
    }

    fn take_pose_session(&self, id: &[u8; 32], sequence: u32) -> Result<Session, Error> {
        let mut sessions = self.poseguard.lock().map_err(|_| Error::Unavailable)?;
        let session = sessions.entries.get(id).ok_or(Error::InvalidMessage)?;
        // Replaying an old ciphertext must not consume the legitimate session.
        if sequence != session.next_sequence {
            return Err(Error::InvalidMessage);
        }
        sessions.entries.remove(id).ok_or(Error::InvalidMessage)
    }
}

impl Session {
    fn apply(&mut self, evaluation: PoseEvaluation, now: Instant) -> Result<Outcome, Error> {
        match evaluation {
            PoseEvaluation::Identity(embedding)
                if self.identity.is_none() && self.target.is_none() =>
            {
                self.identity = Some(embedding);
                self.next_target(now)?;
                Ok(self.capture(None))
            }
            PoseEvaluation::Similarity(similarity)
                if self.identity.is_some() && self.target.is_some() =>
            {
                if !similarity.is_finite() || !(-1.0..=1.0).contains(&similarity) {
                    return Err(Error::Unavailable);
                }
                if similarity < SIMILARITY_THRESHOLD {
                    return Ok(Self::failed(Rejection::IdentityMismatch));
                }
                self.completed += 1;
                if self.completed == CHALLENGES {
                    Ok(Outcome::Complete {
                        passed: true,
                        reason: None,
                    })
                } else {
                    self.next_target(now)?;
                    Ok(self.capture(None))
                }
            }
            PoseEvaluation::Rejected { reason, retryable } => {
                if retryable {
                    Ok(self.capture(Some(reason)))
                } else {
                    Ok(Self::failed(reason))
                }
            }
            _ => Err(Error::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{attestation::Attestor, engine::Engine};
    use selfie_enrollment_sealed_types::{Failure, poseguard::VERSION};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct Attestation;
    impl Attestor for Attestation {
        fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(key.to_vec())
        }
    }
    struct TestEngine {
        replies: Mutex<VecDeque<PoseEvaluation>>,
        supported: bool,
    }
    fn identity() -> FaceEmbedding {
        FaceEmbedding {
            embedding: "reference".into(),
            embedding_type: "face".into(),
            embedding_version: "1".into(),
            embedding_inference_backend: "cpu".into(),
        }
    }
    impl Engine for TestEngine {
        fn extract(&self, _: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error> {
            Ok(Ok(identity()))
        }
        fn check_health(&self) -> Result<(), Error> {
            Ok(())
        }
        fn supports_poseguard(&self) -> bool {
            self.supported
        }
        fn evaluate_pose(
            &self,
            _: &[u8],
            target: Option<PoseTarget>,
            reference: Option<&FaceEmbedding>,
        ) -> Result<PoseEvaluation, Error> {
            assert_eq!(target.is_some(), reference.is_some());
            if let Some(reference) = reference {
                assert_eq!(reference.embedding, "reference");
            }
            Ok(self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected worker call"))
        }
    }
    fn state(replies: Vec<PoseEvaluation>) -> State {
        State::new(
            Arc::new(Attestation),
            Box::new(TestEngine {
                replies: Mutex::new(replies.into()),
                supported: true,
            }),
        )
        .unwrap()
    }
    const KEY: [u8; 32] = [7; 32];
    fn call(state: &State, action: Action, now: Instant) -> Reply {
        let request = Request {
            version: VERSION,
            nonce: [3; 32],
            action,
        };
        let response = state.evaluate_poseguard_at(&request, now).unwrap();
        Reply::decode_authenticated(&response, &KEY, &request.nonce).unwrap()
    }
    fn begin(state: &State, now: Instant) -> Reply {
        call(state, Action::Begin { auth_key: KEY }, now)
    }
    fn submit(state: &State, previous: &Reply, now: Instant) -> Reply {
        call(
            state,
            Action::Submit {
                session_id: previous.session_id,
                sequence: previous.next_sequence,
                image: vec![1],
            },
            now,
        )
    }
    #[test]
    fn success_requires_identity_and_every_challenge_and_cannot_be_replayed() {
        let now = Instant::now();
        let state = state(vec![
            PoseEvaluation::Identity(identity()),
            PoseEvaluation::Similarity(0.8),
            PoseEvaluation::Similarity(0.8),
            PoseEvaluation::Similarity(0.8),
        ]);
        let mut reply = begin(&state, now);
        assert!(matches!(
            reply.outcome,
            Outcome::Capture { target: None, .. }
        ));
        for _ in 0..3 {
            reply = submit(&state, &reply, now);
            assert!(matches!(
                reply.outcome,
                Outcome::Capture {
                    target: Some(_),
                    ..
                }
            ));
        }
        let id = reply.session_id;
        let sequence = reply.next_sequence;
        reply = submit(&state, &reply, now);
        assert!(matches!(
            reply.outcome,
            Outcome::Complete {
                passed: true,
                reason: None
            }
        ));
        assert!(state.poseguard.lock().unwrap().entries.is_empty());
        let replay = Request {
            version: VERSION,
            nonce: [1; 32],
            action: Action::Submit {
                session_id: id,
                sequence,
                image: vec![1],
            },
        };
        assert!(matches!(
            state.evaluate_poseguard_at(&replay, now),
            Err(Error::InvalidMessage)
        ));
    }
    #[test]
    fn mismatch_and_analysis_failure_are_terminal_but_never_disable_vanilla() {
        for evaluation in [
            PoseEvaluation::Similarity(0.39),
            PoseEvaluation::Rejected {
                reason: Rejection::AnalysisFailed,
                retryable: false,
            },
        ] {
            let state = state(vec![PoseEvaluation::Identity(identity()), evaluation]);
            let now = Instant::now();
            let first = begin(&state, now);
            let centered = submit(&state, &first, now);
            let final_reply = submit(&state, &centered, now);
            assert!(matches!(
                final_reply.outcome,
                Outcome::Complete { passed: false, .. }
            ));
            assert!(state.poseguard.lock().unwrap().entries.is_empty());
            assert!(state.engine.extract(&[1]).unwrap().is_ok());
        }
    }
    #[test]
    fn pose_retry_preserves_target_and_deadline_but_consumes_sequence() {
        let state = state(vec![
            PoseEvaluation::Identity(identity()),
            PoseEvaluation::Rejected {
                reason: Rejection::PoseMismatch,
                retryable: true,
            },
        ]);
        let now = Instant::now();
        let initial = begin(&state, now);
        let centered = submit(&state, &initial, now);
        let deadline = state.poseguard.lock().unwrap().entries[&centered.session_id].deadline;
        let retried = submit(&state, &centered, now + Duration::from_secs(1));
        let guard = state.poseguard.lock().unwrap();
        let session = &guard.entries[&retried.session_id];
        assert_eq!(session.deadline, deadline);
        assert_eq!(retried.next_sequence, centered.next_sequence + 1);
        let Outcome::Capture { target, .. } = &centered.outcome else {
            panic!("capture required")
        };
        assert_eq!(session.target, *target);
        assert!(matches!(
            retried.outcome,
            Outcome::Capture {
                retry: Some(Rejection::PoseMismatch),
                ..
            }
        ));
    }
    #[test]
    fn timeout_restarts_sequence_retains_identity_and_exhaustion_fails() {
        let state = state(vec![
            PoseEvaluation::Identity(identity()),
            PoseEvaluation::Similarity(0.8),
        ]);
        let now = Instant::now();
        let started = begin(&state, now);
        let centered = submit(&state, &started, now);
        let mut reply = submit(&state, &centered, now);
        for attempt in 2..=3 {
            reply = submit(
                &state,
                &reply,
                now + Duration::from_secs(16 * u64::from(attempt - 1)),
            );
            assert!(
                matches!(reply.outcome, Outcome::Capture {challenge_index:0,sequence_attempt, ..} if sequence_attempt == attempt)
            );
            assert!(
                state.poseguard.lock().unwrap().entries[&reply.session_id]
                    .identity
                    .is_some()
            );
        }
        reply = submit(&state, &reply, now + Duration::from_secs(48));
        assert!(matches!(
            reply.outcome,
            Outcome::Complete {
                passed: false,
                reason: Some(Rejection::AttemptsExhausted)
            }
        ));
    }
    #[test]
    fn wrong_sequence_does_not_consume_session_and_cancel_does() {
        let state = state(vec![]);
        let now = Instant::now();
        let initial = begin(&state, now);
        let wrong = Request {
            version: VERSION,
            nonce: [2; 32],
            action: Action::Submit {
                session_id: initial.session_id,
                sequence: 2,
                image: vec![1],
            },
        };
        assert!(matches!(
            state.evaluate_poseguard_at(&wrong, now),
            Err(Error::InvalidMessage)
        ));
        assert_eq!(state.poseguard.lock().unwrap().entries.len(), 1);
        let reply = call(
            &state,
            Action::Cancel {
                session_id: initial.session_id,
                sequence: 1,
            },
            now,
        );
        assert!(matches!(
            reply.outcome,
            Outcome::Complete {
                passed: false,
                reason: Some(Rejection::Cancelled)
            }
        ));
        assert!(state.poseguard.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn sessions_are_bounded_and_expired_without_host_cooperation() {
        let state = state(vec![]);
        let now = Instant::now();
        for _ in 0..MAX_SESSIONS {
            begin(&state, now);
        }
        let request = Request {
            version: VERSION,
            nonce: [2; 32],
            action: Action::Begin { auth_key: KEY },
        };
        assert!(matches!(
            state.evaluate_poseguard_at(&request, now),
            Err(Error::Busy)
        ));
        state
            .poseguard
            .lock()
            .unwrap()
            .expire(now + Duration::from_secs(SESSION_TTL_SECS));
        assert!(state.poseguard.lock().unwrap().entries.is_empty());
        begin(&state, now + Duration::from_secs(SESSION_TTL_SECS));
    }
    #[test]
    fn unsupported_worker_leaves_vanilla_available_and_allocates_nothing() {
        let state = State::new(
            Arc::new(Attestation),
            Box::new(TestEngine {
                replies: Mutex::new(VecDeque::new()),
                supported: false,
            }),
        )
        .unwrap();
        let request = Request {
            version: VERSION,
            nonce: [2; 32],
            action: Action::Begin { auth_key: KEY },
        };
        assert!(matches!(
            state.evaluate_poseguard(&request),
            Err(Error::Unavailable)
        ));
        assert!(state.engine.extract(&[1]).unwrap().is_ok());
        assert!(state.poseguard.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn targets_are_separated_with_disjoint_acceptance_regions() {
        let mut previous = PoseTarget { pitch: 0, yaw: 0 };
        for _ in 0..100 {
            let next = generate_target(Some(previous)).unwrap();
            next.validate().unwrap();
            let pitch = (next.pitch - previous.pitch).abs();
            let yaw = (next.yaw - previous.yaw).abs();
            assert!(pitch >= 10 && yaw >= 15 && (pitch > 20 || yaw > 20));
            previous = next;
        }
    }
    #[tokio::test]
    async fn shadow_messages_use_the_sealed_channel_and_return_authenticated_results() {
        use pontifex::{ChannelConsumer, ChannelDomain};
        use selfie_enrollment_api_types::CHANNEL_DOMAIN;
        use selfie_enrollment_enclave_types::ExtractRequest;
        let state = Arc::new(state(vec![PoseEvaluation::Identity(identity())]));
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &state.assignment().await.unwrap().public_key,
        )
        .unwrap();
        let request = Request {
            version: VERSION,
            nonce: [9; 32],
            action: Action::Begin { auth_key: KEY },
        };
        let (ciphertext, opener) = consumer
            .seal_to_enclave(&request.encode().unwrap())
            .unwrap();
        let response = state.extract(ExtractRequest { ciphertext }).await.unwrap();
        let plaintext = opener.open_from_enclave(&response.ciphertext).unwrap();
        let reply = Reply::decode_authenticated(&plaintext, &KEY, &request.nonce).unwrap();
        assert!(matches!(
            reply.outcome,
            Outcome::Capture { target: None, .. }
        ));
        assert!(Reply::decode_authenticated(&plaintext, &[8; 32], &request.nonce).is_err());
    }
}
