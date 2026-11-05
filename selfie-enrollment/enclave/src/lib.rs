//! Public enclave broker for sandboxed Selfie Check embedding extraction and, when the release
//! provides its trusted context, attested v2 web enrollment with a user-owned Face PCP.
pub mod attestation;
pub mod engine;
pub mod enrollment;
pub mod rng;
#[cfg(target_os = "linux")]
pub mod runtime;
use attestation::{AttestedKey, Attestor, MAX_CACHED_AGE};
use engine::Engine;
use pontifex::{ChannelDomain, ChannelEnclave};
use selfie_enrollment_api_types::{CHANNEL_DOMAIN, MAX_REQUEST_BYTES};
use selfie_enrollment_enclave_types::{Error, ExtractRequest, ExtractResponse, KeyAttestation};
use selfie_enrollment_sealed_types::{EmbeddingResult, Failure, Request};
use std::sync::Arc;

/// No worker replacement or key rotation occurs inside an enclave boot.
pub struct State {
    channel: ChannelEnclave,
    attested: AttestedKey,
    engine: Box<dyn Engine>,
    processing: Arc<tokio::sync::Semaphore>,
    /// Absent until the release supplies Face-AMPC keys and the worker measurement.
    enrollment: Option<enrollment::Producer>,
}
impl State {
    pub fn new(attestor: Arc<dyn Attestor>, engine: Box<dyn Engine>) -> Result<Self, Error> {
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
            engine,
            processing: Arc::new(tokio::sync::Semaphore::new(1)),
            enrollment: None,
        })
    }
    /// Enables sealed enrollment requests; without it they fail as `Unavailable`.
    #[must_use]
    pub fn with_enrollment(mut self, producer: enrollment::Producer) -> Self {
        self.enrollment = Some(producer);
        self
    }
    pub fn refresh(&mut self) -> tokio::task::JoinHandle<()> {
        self.attested.start_refresh()
    }
    pub fn health(&self) -> Result<(), Error> {
        self.engine.check_health()
    }
    pub async fn assignment(&self) -> Result<KeyAttestation, Error> {
        self.health()?;
        Ok(KeyAttestation {
            document: self.attested.document().await,
            public_key: self.channel.public_key(),
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
            let encoded = match Request::decode(&plain) {
                // Undecodable plaintext keeps the v1 reply that existing clients expect.
                Err(_) => EmbeddingResult::Failed {
                    reason: Failure::InvalidRequest,
                }
                .encode(),
                Ok(Request::Embedding(input)) => match state.engine.extract(&input.image)? {
                    Ok(embedding) => EmbeddingResult::Success { embedding },
                    Err(reason) => EmbeddingResult::Failed { reason },
                }
                .encode(),
                Ok(Request::Enrollment(input)) => state.enroll_sealed(&input)?.encode(),
            }
            .map_err(|_| Error::Unavailable)?;
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
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use crypto_box::SecretKey;
    use pontifex::ChannelConsumer;
    use rand::rngs::OsRng;
    use selfie_enrollment_api_types::ENROLLMENT_PROTOCOL_VERSION;
    use selfie_enrollment_identity::{
        AttestationFailed, CaptureAttestor, NONCE_BYTES, USER_DATA_BYTES,
    };
    use selfie_enrollment_sealed_types::{
        ENROLLMENT_FIELDS, EmbeddingRequest, EnrollmentRequest, EnrollmentResult, FaceEmbedding,
    };
    struct TestAttestor;
    impl Attestor for TestAttestor {
        fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(key.to_vec())
        }
    }
    struct FakeEngine;
    impl Engine for FakeEngine {
        fn extract(&self, _: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error> {
            Ok(Ok(FaceEmbedding {
                embedding: "AA==".into(),
                embedding_type: "test".into(),
                embedding_version: "1".into(),
                embedding_inference_backend: "test".into(),
            }))
        }
        fn check_health(&self) -> Result<(), Error> {
            Ok(())
        }
    }
    fn state() -> Arc<State> {
        Arc::new(State::new(Arc::new(TestAttestor), Box::new(FakeEngine)).unwrap())
    }
    /// A 512-dimension embedding the share generator accepts, or a panic if `forbid`.
    struct EnrollEngine {
        forbid: bool,
    }
    impl Engine for EnrollEngine {
        fn extract(&self, _: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error> {
            assert!(
                !self.forbid,
                "invalid enrollment requests must not reach extraction"
            );
            let mut vector = (512_u64).to_le_bytes().to_vec();
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
    struct CaptureDocument;
    impl CaptureAttestor for CaptureDocument {
        fn attest(
            &self,
            _: &[u8; NONCE_BYTES],
            _: &[u8; USER_DATA_BYTES],
        ) -> Result<Vec<u8>, AttestationFailed> {
            Ok(b"capture-document".to_vec())
        }
    }
    fn enrolling_state(forbid: bool) -> Arc<State> {
        let context = enrollment::TrustedContext::new(
            std::array::from_fn(|_| SecretKey::generate(&mut OsRng).public_key()),
            [0x5a; 48],
        )
        .unwrap();
        Arc::new(
            State::new(Arc::new(TestAttestor), Box::new(EnrollEngine { forbid }))
                .unwrap()
                .with_enrollment(enrollment::Producer::new(
                    context,
                    Arc::new(CaptureDocument),
                )),
        )
    }
    async fn sealed_enrollment(
        state: &Arc<State>,
        sub: &str,
        custody: &SecretKey,
    ) -> Result<EnrollmentResult, Error> {
        let assignment = state.assignment().await.unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &assignment.public_key,
        )
        .unwrap();
        let request = EnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            image: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
            sub: sub.into(),
            custody_public_key: custody.public_key().as_bytes().to_vec(),
        };
        let (sealed, opener) = consumer
            .seal_to_enclave(&request.encode().unwrap())
            .unwrap();
        let response = state.extract(ExtractRequest { ciphertext: sealed }).await?;
        assert!(response.ciphertext.len() <= selfie_enrollment_api_types::MAX_RESPONSE_BYTES);
        let opened = opener.open_from_enclave(&response.ciphertext).unwrap();
        Ok(EnrollmentResult::decode(&opened).unwrap())
    }
    #[tokio::test]
    async fn sealed_enrollment_returns_the_bundle_and_a_user_owned_pcp() {
        let state = enrolling_state(false);
        let custody = SecretKey::generate(&mut OsRng);
        let result = sealed_enrollment(&state, "0x1f", &custody).await.unwrap();
        let EnrollmentResult::Success { enrollment } = &result else {
            panic!("expected an enrollment")
        };
        let names: Vec<_> = enrollment.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ENROLLMENT_FIELDS);
        let value = |name: &str| {
            enrollment
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.value.as_str())
                .unwrap()
        };
        assert_eq!(value("contract_version"), "2");
        assert_eq!(value("sub"), "0x1f");
        assert_eq!(
            STANDARD.decode(&enrollment.attestation_header).unwrap(),
            b"capture-document"
        );
        // Only the user's custody key opens the PCP: a gzip-compressed archive.
        let pcp = custody.unseal(&enrollment.encrypted_custody).unwrap();
        assert!(pcp.starts_with(&[0x1f, 0x8b]));
        assert!(
            SecretKey::generate(&mut OsRng)
                .unseal(&enrollment.encrypted_custody)
                .is_err()
        );
        assert!(
            state.processing.try_acquire().is_ok(),
            "the permit is released"
        );
    }
    #[tokio::test]
    async fn sealed_enrollment_without_a_producer_is_unavailable() {
        let custody = SecretKey::generate(&mut OsRng);
        assert!(matches!(
            sealed_enrollment(&state(), "0x1f", &custody).await,
            Err(Error::Unavailable)
        ));
    }
    #[tokio::test]
    async fn sealed_enrollment_rejects_non_canonical_subjects_before_extraction() {
        let state = enrolling_state(true);
        let custody = SecretKey::generate(&mut OsRng);
        for sub in [
            "0x01f",
            "0x1F",
            "0x0",
            "0x000000000000000000000000000000000000000000000000000000000000001f",
        ] {
            assert!(matches!(
                sealed_enrollment(&state, sub, &custody).await.unwrap(),
                EnrollmentResult::Failed {
                    reason: Failure::InvalidRequest
                }
            ));
        }
    }
    #[tokio::test]
    async fn sealed_round_trip_allows_resubmission_and_uses_request_response_key() {
        let state = state();
        let assignment = state.assignment().await.unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &assignment.public_key,
        )
        .unwrap();
        let request = EmbeddingRequest {
            version: 1,
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
        state
            .extract(ExtractRequest { ciphertext: sealed })
            .await
            .expect("same-boot resubmission is allowed");
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
    async fn assignments_reuse_the_boot_key_and_wrong_boot_cannot_open() {
        let state = state();
        let assignment = state.assignment().await.unwrap();
        for _ in 0..64 {
            let next = state.assignment().await.unwrap();
            assert_eq!(next.public_key, assignment.public_key);
        }
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &assignment.public_key,
        )
        .unwrap();
        let request = EmbeddingRequest {
            version: 1,
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
    }
}
