//! Native enclave producer: extract, assemble, attest and encrypt custody data.
//!
//! This blocking operation is separate from the existing embedding RPC. A runtime
//! adapter must obtain requests/custody keys from the authenticated sealed channel
//! and provision measured AMPC keys, the actual worker measurement and a native
//! v3 identity/proof source before exposing it. No browser/host-supplied clock,
//! capture ID, worker hash, AMPC keys or identity are accepted in `CaptureRequest`.

use std::time::{SystemTime, UNIX_EPOCH};

use crypto_box::PublicKey;
use rand::rngs::OsRng;
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;
use selfie_enrollment_identity::{
    Capture, CaptureAttestor, Form, Inputs, Subject, assemble, custody,
};
use uuid::Uuid;

use crate::State;
use selfie_enrollment_sealed_types::Failure;

/// Public outputs of the enclave-held v3 prover. Its secret never enters a response.
pub struct IdentityAuthorization {
    pub id_commitment: String,
    pub x_zkp_proof: String,
}

/// The runtime must supply a real enclave-resident prover, including its identity
/// retention/retrieval lifecycle. There is deliberately no default or synthetic implementation.
pub trait IdentitySource: Send + Sync {
    /// # Errors
    /// Fail closed when identity/proof generation is unavailable.
    fn authorize(&self, capture_id: Uuid, captured_at: u64)
    -> Result<IdentityAuthorization, Error>;
}

/// Construct only from the measured enclave's release configuration and verified
/// bootstrap worker measurement. Never deserialize this from a client or host request.
pub struct TrustedContext {
    recipient_keys: [PublicKey; 3],
    worker_sha384: [u8; 48],
    identity: Box<dyn IdentitySource>,
}

impl TrustedContext {
    /// # Errors
    /// Reject unsuitable AMPC keys or an absent worker measurement.
    pub fn new(
        recipient_keys: [PublicKey; 3],
        worker_sha384: [u8; 48],
        identity: Box<dyn IdentitySource>,
    ) -> Result<Self, Error> {
        embedding_shares::validate_recipients(&recipient_keys)
            .map_err(|_| Error::InvalidRequest)?;
        if worker_sha384 == [0; 48] {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            recipient_keys,
            worker_sha384,
            identity,
        })
    }
}

/// Obtain these bytes through the verified encrypted enrollment channel. The image
/// must be PNG; JPEG-to-PNG conversion is not silently delegated to the host.
pub struct CaptureRequest<'a> {
    pub image_png: &'a [u8],
    pub subject: Subject<'a>,
    pub custody_key: &'a PublicKey,
}

/// Contains submission metadata and encrypted custody data, never the image,
/// raw embedding, plaintext shares or v3 identity secret. No Debug implementation.
pub struct PreparedEnrollment {
    pub id_commitment: String,
    pub x_zkp_proof: String,
    pub form: Form,
    pub attestation_header: String,
    pub encrypted_custody: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid enrollment request")]
    InvalidRequest,
    #[error("enrollment worker busy")]
    Busy,
    #[error("capture rejected")]
    Capture(Failure),
    #[error("enrollment producer unavailable")]
    Unavailable,
}

impl State {
    /// Runs on an enclave blocking thread; holds the existing processing permit
    /// until extraction, attestation and custody encryption all finish.
    ///
    /// # Errors
    /// Reject invalid inputs, worker contention, failed extraction or unavailable
    /// identity, attestation or custody encryption. No partial enrollment is returned.
    pub fn prepare_enrollment(
        &self,
        request: CaptureRequest<'_>,
        context: &TrustedContext,
        attestor: &dyn CaptureAttestor,
    ) -> Result<PreparedEnrollment, Error> {
        if request.image_png.len() > MAX_IMAGE_BYTES
            || !request.image_png.starts_with(b"\x89PNG\r\n\x1a\n")
            || request.subject.ownership_proof.is_empty()
            || request.subject.ownership_proof.len()
                > selfie_enrollment_identity::MAX_OWNERSHIP_PROOF_BYTES
        {
            return Err(Error::InvalidRequest);
        }
        embedding_shares::validate_recipients(std::slice::from_ref(request.custody_key))
            .map_err(|_| Error::InvalidRequest)?;
        let _permit = self.processing.try_acquire().map_err(|_| Error::Busy)?;
        let embedding = self
            .engine
            .extract(request.image_png)
            .map_err(|_| Error::Unavailable)?
            .map_err(Error::Capture)?;
        let captured_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
        let capture_id = Uuid::new_v4();
        let identity = context.identity.authorize(capture_id, captured_at)?;
        if identity.x_zkp_proof.is_empty() || identity.x_zkp_proof.len() > 64 * 1024 {
            return Err(Error::Unavailable);
        }
        let inputs = Inputs {
            capture: Capture {
                capture_id,
                captured_at,
                image_png: request.image_png,
                embedding: &embedding,
            },
            subject: request.subject,
            id_commitment: &identity.id_commitment,
            pcp_version: "1",
            recipient_keys: &context.recipient_keys,
            worker_sha384: &context.worker_sha384,
        };
        let enrollment = assemble(&inputs, attestor, &mut OsRng).map_err(|_| Error::Unavailable)?;
        let encrypted_custody = custody::encrypt(&enrollment, request.custody_key, &mut OsRng)
            .map_err(|_| Error::Unavailable)?;
        let attestation_header = enrollment.attestation_header();
        Ok(PreparedEnrollment {
            id_commitment: enrollment.id_commitment,
            x_zkp_proof: identity.x_zkp_proof,
            form: enrollment.form,
            attestation_header,
            encrypted_custody,
        })
        // enrollment.associated_data and the worker embedding erase owned buffers on drop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use crypto_box::SecretKey;
    use selfie_enrollment_enclave_types::Error as EnclaveError;
    use selfie_enrollment_identity::{
        AttestationFailed, NONCE_BYTES, USER_DATA_BYTES, binding_digest, user_data,
    };
    use selfie_enrollment_sealed_types::FaceEmbedding;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct BootAttestor;
    impl crate::attestation::Attestor for BootAttestor {
        fn attest_public_key(&self, key: &[u8]) -> Result<Vec<u8>, EnclaveError> {
            Ok(key.to_vec())
        }
    }
    struct Engine {
        reject: bool,
    }
    impl crate::engine::Engine for Engine {
        fn extract(&self, image: &[u8]) -> Result<Result<FaceEmbedding, Failure>, EnclaveError> {
            assert_eq!(image, b"\x89PNG\r\n\x1a\nfixture");
            if self.reject {
                return Ok(Err(Failure::QualityRejected));
            }
            let mut vector = (512_u64).to_le_bytes().to_vec();
            vector.resize(8 + 512 * 4, 0);
            Ok(Ok(FaceEmbedding {
                embedding: STANDARD.encode(vector),
                embedding_type: "ghostfacenet_flipped_mean".into(),
                embedding_version: "2.0.0".into(),
                embedding_inference_backend: "face-engine".into(),
            }))
        }
        fn check_health(&self) -> Result<(), EnclaveError> {
            Ok(())
        }
    }
    struct Identity;
    impl IdentitySource for Identity {
        fn authorize(
            &self,
            capture: Uuid,
            captured_at: u64,
        ) -> Result<IdentityAuthorization, Error> {
            assert!(!capture.is_nil());
            assert!(captured_at > 0);
            Ok(IdentityAuthorization {
                id_commitment: format!("0x{:064x}", 0x123),
                x_zkp_proof: "synthetic-test-only".into(),
            })
        }
    }
    #[derive(Default)]
    struct Attestor {
        calls: AtomicUsize,
        nonce: Mutex<Vec<u8>>,
        user_data: Mutex<Vec<u8>>,
        fail: bool,
    }
    impl CaptureAttestor for Attestor {
        fn attest(
            &self,
            nonce: &[u8; NONCE_BYTES],
            data: &[u8; USER_DATA_BYTES],
        ) -> Result<Vec<u8>, AttestationFailed> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.nonce.lock().unwrap() = nonce.to_vec();
            *self.user_data.lock().unwrap() = data.to_vec();
            if self.fail {
                return Err(AttestationFailed);
            }
            Ok(b"synthetic-document".to_vec())
        }
    }
    fn context() -> TrustedContext {
        TrustedContext::new(
            std::array::from_fn(|_| SecretKey::generate(&mut OsRng).public_key()),
            [0x5a; 48],
            Box::new(Identity),
        )
        .unwrap()
    }
    fn request(key: &PublicKey) -> CaptureRequest<'_> {
        CaptureRequest {
            image_png: b"\x89PNG\r\n\x1a\nfixture",
            subject: Subject {
                sub: "0x1f",
                challenge_id: Uuid::from_u128(0x1234),
                ownership_proof: b"fixture-proof",
            },
            custody_key: key,
        }
    }

    #[test]
    fn successful_extraction_returns_only_public_fields_and_encrypted_custody() {
        let state = State::new(Arc::new(BootAttestor), Box::new(Engine { reject: false })).unwrap();
        let key = SecretKey::generate(&mut OsRng);
        let attestor = Attestor::default();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let prepared = state
            .prepare_enrollment(request(&key.public_key()), &context(), &attestor)
            .unwrap();
        assert_eq!(prepared.id_commitment, format!("0x{:064x}", 0x123));
        assert_eq!(prepared.x_zkp_proof, "synthetic-test-only");
        assert!(prepared.form.timestamp.parse::<u64>().unwrap() >= before);
        assert!(!Uuid::parse_str(&prepared.form.capture_id).unwrap().is_nil());
        assert_eq!(
            *attestor.nonce.lock().unwrap(),
            binding_digest(&prepared.id_commitment, &prepared.form)
        );
        assert_eq!(*attestor.user_data.lock().unwrap(), user_data(&[0x5a; 48]));
        assert_eq!(
            STANDARD.decode(prepared.attestation_header).unwrap(),
            b"synthetic-document"
        );
        let custody = key.unseal(&prepared.encrypted_custody).unwrap();
        assert!(custody.starts_with(&[0x1f, 0x8b]));
        assert!(
            SecretKey::generate(&mut OsRng)
                .unseal(&prepared.encrypted_custody)
                .is_err()
        );
        assert_eq!(attestor.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejected_images_busy_worker_and_attestation_failure_do_not_return_enrollment() {
        let state = State::new(Arc::new(BootAttestor), Box::new(Engine { reject: true })).unwrap();
        let key = SecretKey::generate(&mut OsRng).public_key();
        let attestor = Attestor::default();
        assert!(matches!(
            state.prepare_enrollment(request(&key), &context(), &attestor),
            Err(Error::Capture(Failure::QualityRejected))
        ));
        assert_eq!(attestor.calls.load(Ordering::SeqCst), 0);
        let permit = state.processing.try_acquire().unwrap();
        assert!(matches!(
            state.prepare_enrollment(request(&key), &context(), &attestor),
            Err(Error::Busy)
        ));
        drop(permit);
        let state = State::new(Arc::new(BootAttestor), Box::new(Engine { reject: false })).unwrap();
        let attestor = Attestor {
            fail: true,
            ..Default::default()
        };
        assert!(matches!(
            state.prepare_enrollment(request(&key), &context(), &attestor),
            Err(Error::Unavailable)
        ));
        assert!(state.processing.try_acquire().is_ok());
    }

    #[test]
    fn invalid_custody_keys_and_non_png_inputs_fail_before_attestation() {
        let state = State::new(Arc::new(BootAttestor), Box::new(Engine { reject: false })).unwrap();
        let bad_key = PublicKey::from([0; 32]);
        let attestor = Attestor::default();
        assert!(matches!(
            state.prepare_enrollment(request(&bad_key), &context(), &attestor),
            Err(Error::InvalidRequest)
        ));
        let key = SecretKey::generate(&mut OsRng).public_key();
        let mut input = request(&key);
        input.image_png = b"jpeg";
        assert!(matches!(
            state.prepare_enrollment(input, &context(), &attestor),
            Err(Error::InvalidRequest)
        ));
        assert_eq!(attestor.calls.load(Ordering::SeqCst), 0);
    }
}
