//! Public enclave broker for sandboxed Selfie Check embedding extraction.
pub mod attestation;
#[cfg(target_os = "linux")]
pub mod bootstrap;
pub mod engine;
pub mod rng;
#[cfg(target_os = "linux")]
pub mod runtime;
use attestation::{AttestedKey, Attestor, MAX_CACHED_AGE};
use engine::Engine;
use pontifex::{ChannelDomain, ChannelEnclave};
use rand::RngCore;
use selfie_enrollment_api_types::{CHANNEL_DOMAIN, MAX_REQUEST_BYTES};
use selfie_enrollment_enclave_types::{Error, ExtractRequest, ExtractResponse, KeyAttestation};
use selfie_enrollment_sealed_types::{EmbeddingRequest, EmbeddingResult, Failure, WorkerIdentity};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const ASSIGNMENT_TTL: Duration = Duration::from_secs(60);
const MAX_ASSIGNMENTS: usize = 32;

/// No worker replacement or key rotation occurs inside an enclave boot.
pub struct State {
    channel: ChannelEnclave,
    attested: AttestedKey,
    identity: WorkerIdentity,
    engine: Mutex<Box<dyn Engine>>,
    assignments: Mutex<BTreeMap<[u8; 32], Instant>>,
    processing: Arc<tokio::sync::Semaphore>,
}
impl State {
    pub fn new(
        attestor: Arc<dyn Attestor>,
        engine: Box<dyn Engine>,
        identity: WorkerIdentity,
    ) -> Result<Self, Error> {
        identity.validate().map_err(|_| Error::Unavailable)?;
        let channel = ChannelEnclave::generate(ChannelDomain::new(CHANNEL_DOMAIN))
            .map_err(|_| Error::Unavailable)?;
        let attested = AttestedKey::new(
            attestor,
            channel.public_key_commitment().to_vec(),
            MAX_CACHED_AGE,
        )?;
        Ok(Self {
            channel,
            attested,
            identity,
            engine: Mutex::new(engine),
            assignments: Mutex::new(BTreeMap::new()),
            processing: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    pub fn refresh(&mut self) -> tokio::task::JoinHandle<()> {
        self.attested.start_refresh()
    }
    pub fn health(&self) -> Result<(), Error> {
        match self.engine.try_lock() {
            Ok(engine) => engine.check_health(),
            Err(std::sync::TryLockError::WouldBlock) => Ok(()),
            Err(_) => Err(Error::Unavailable),
        }
    }
    pub async fn assignment(&self) -> Result<KeyAttestation, Error> {
        self.health()?;
        let document = self.attested.document().await;
        let now = Instant::now();
        let mut pending = self.assignments.lock().map_err(|_| Error::Unavailable)?;
        pending.retain(|_, created| now.duration_since(*created) < ASSIGNMENT_TTL);
        if pending.len() >= MAX_ASSIGNMENTS {
            return Err(Error::Busy);
        }
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        if pending.insert(nonce, now).is_some() {
            return Err(Error::Unavailable);
        }
        Ok(KeyAttestation {
            document,
            public_key: self.channel.public_key(),
            nonce,
        })
    }
    /// Permit moves into the blocking task: cancellation cannot release it while inference runs.
    pub async fn extract(
        self: &Arc<Self>,
        request: ExtractRequest,
    ) -> Result<ExtractResponse, Error> {
        if request.ciphertext.len() > MAX_REQUEST_BYTES {
            return Err(Error::InvalidMessage);
        }
        let permit = self
            .processing
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (plain, sealer) = state
                .channel
                .open(&request.ciphertext)
                .map_err(|_| Error::ReassignRequired)?;
            let result = match EmbeddingRequest::decode(&plain) {
                Err(_) => EmbeddingResult::Failed {
                    reason: Failure::InvalidRequest,
                },
                Ok(input) => {
                    let created = state
                        .assignments
                        .lock()
                        .map_err(|_| Error::Unavailable)?
                        .remove(&input.nonce)
                        .ok_or(Error::ReassignRequired)?;
                    if created.elapsed() >= ASSIGNMENT_TTL {
                        return Err(Error::ReassignRequired);
                    }
                    let mut engine = state.engine.lock().map_err(|_| Error::Unavailable)?;
                    match engine.extract(&input.image, &state.identity)? {
                        Ok(embedding) => EmbeddingResult::Success { embedding },
                        Err(reason) => EmbeddingResult::Failed { reason },
                    }
                }
            };
            let encoded = result.encode().map_err(|_| Error::Unavailable)?;
            let ciphertext = sealer.seal(&encoded).map_err(|_| Error::Unavailable)?;
            Ok(ExtractResponse { ciphertext })
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pontifex::ChannelConsumer;
    use selfie_enrollment_sealed_types::Embedding;
    struct TestAttestor;
    impl Attestor for TestAttestor {
        fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(key.to_vec())
        }
    }
    struct FakeEngine;
    impl Engine for FakeEngine {
        fn extract(
            &mut self,
            _: &[u8],
            identity: &WorkerIdentity,
        ) -> Result<Result<Embedding, Failure>, Error> {
            Ok(Ok(Embedding {
                vector: "AA==".into(),
                embedding_type: "test".into(),
                version: "1".into(),
                inference_backend: "test".into(),
                worker: identity.clone(),
            }))
        }
        fn check_health(&self) -> Result<(), Error> {
            Ok(())
        }
    }
    fn state() -> Arc<State> {
        Arc::new(
            State::new(
                Arc::new(TestAttestor),
                Box::new(FakeEngine),
                WorkerIdentity {
                    profile: selfie_enrollment_api_types::PROFILE.into(),
                    executable_sha384: "a".repeat(96),
                },
            )
            .unwrap(),
        )
    }
    #[tokio::test]
    async fn sealed_round_trip_is_single_use_and_response_bound() {
        let state = state();
        let assignment = state.assignment().await.unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &assignment.public_key,
        )
        .unwrap();
        let request = EmbeddingRequest {
            version: 1,
            nonce: assignment.nonce,
            image: vec![1, 2, 3],
        };
        let (sealed, opener) = consumer
            .seal_to_enclave(&request.encode().unwrap())
            .unwrap();
        let response = state
            .extract(ExtractRequest {
                ciphertext: sealed.clone(),
            })
            .await
            .unwrap();
        let opened = opener.open_from_enclave(&response.ciphertext).unwrap();
        assert!(matches!(
            EmbeddingResult::decode(&opened).unwrap(),
            EmbeddingResult::Success { .. }
        ));
        assert!(matches!(
            state.extract(ExtractRequest { ciphertext: sealed }).await,
            Err(Error::ReassignRequired)
        ));
        let (_, other_opener) = consumer
            .seal_to_enclave(&request.encode().unwrap())
            .unwrap();
        assert!(
            other_opener
                .open_from_enclave(&response.ciphertext)
                .is_err()
        );
    }
    #[tokio::test]
    async fn bounded_assignments_expire_and_wrong_boot_cannot_open() {
        let state = state();
        let assignment = state.assignment().await.unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &assignment.public_key,
        )
        .unwrap();
        let request = EmbeddingRequest {
            version: 1,
            nonce: assignment.nonce,
            image: vec![1],
        };
        let (sealed, _) = consumer
            .seal_to_enclave(&request.encode().unwrap())
            .unwrap();
        let another_boot = super::tests::state();
        assert!(matches!(
            another_boot
                .extract(ExtractRequest {
                    ciphertext: sealed.clone()
                })
                .await,
            Err(Error::ReassignRequired)
        ));
        state
            .assignments
            .lock()
            .unwrap()
            .insert(assignment.nonce, Instant::now() - ASSIGNMENT_TTL);
        assert!(matches!(
            state.extract(ExtractRequest { ciphertext: sealed }).await,
            Err(Error::ReassignRequired)
        ));
        for _ in 0..MAX_ASSIGNMENTS {
            state.assignment().await.unwrap();
        }
        assert!(matches!(state.assignment().await, Err(Error::Busy)));
    }
}
