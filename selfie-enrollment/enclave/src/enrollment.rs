//! Native enclave producer: extract, assemble, attest and encrypt custody data for
//! signup-service's v4-only web enrollment, `PUT /api/v2/identity`.
//!
//! The browser sends a capture, its canonical v4 subject and its custody public key over the
//! attested channel ([`State::enroll_sealed`]). The enclave returns the attested capture fields,
//! the Nitro attestation header and the user's Face PCP sealed to that custody key. The browser
//! adds its v4 challenge and ownership proof and submits the request itself; signup-service
//! verifies subject ownership. There is no v3 identity. Clock, capture ID, AMPC recipient keys
//! and the worker measurement remain enclave-controlled.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto_box::PublicKey;
use rand::rngs::OsRng;
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;
use selfie_enrollment_enclave_types::Error as EnclaveError;
use selfie_enrollment_identity::{
    Capture, CaptureAttestor, Form, Inputs, assemble, custody, validate_sub,
};
use selfie_enrollment_sealed_types::{
    EnrollmentBundle, EnrollmentField, EnrollmentRequest, EnrollmentResult, Failure,
};
use uuid::Uuid;

use crate::State;

/// Construct only from the measured enclave's release configuration and verified
/// bootstrap worker measurement. Never deserialize this from a client or host request.
pub struct TrustedContext {
    recipient_keys: [PublicKey; 3],
    worker_sha384: [u8; 48],
}

impl TrustedContext {
    /// # Errors
    /// Reject unsuitable AMPC keys or an absent worker measurement.
    pub fn new(recipient_keys: [PublicKey; 3], worker_sha384: [u8; 48]) -> Result<Self, Error> {
        embedding_shares::validate_recipients(&recipient_keys)
            .map_err(|_| Error::InvalidRequest)?;
        if worker_sha384 == [0; 48] {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            recipient_keys,
            worker_sha384,
        })
    }
}

/// The enclave's enrollment capability: its trusted context and per-capture attestor.
pub struct Producer {
    context: TrustedContext,
    attestor: Arc<dyn CaptureAttestor + Send + Sync>,
}

impl Producer {
    #[must_use]
    pub fn new(context: TrustedContext, attestor: Arc<dyn CaptureAttestor + Send + Sync>) -> Self {
        Self { context, attestor }
    }
}

/// Obtain these bytes through the verified encrypted enrollment channel. The image
/// must be PNG; JPEG-to-PNG conversion is not silently delegated to the host.
pub struct CaptureRequest<'a> {
    pub image_png: &'a [u8],
    /// The browser's canonical v4 subject, bound into the attested capture.
    pub sub: &'a str,
    /// The user's custody public key; the PCP is sealed to it.
    pub custody_key: &'a PublicKey,
}

/// Contains submission metadata and encrypted custody data, never the image,
/// raw embedding, plaintext shares or identity secrets. No Debug implementation.
/// The browser submits `form`, plus its challenge and proof, with `attestation_header`.
pub struct PreparedEnrollment {
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

fn validate(request: &CaptureRequest<'_>) -> Result<(), Error> {
    if request.image_png.len() > MAX_IMAGE_BYTES
        || !request.image_png.starts_with(b"\x89PNG\r\n\x1a\n")
    {
        return Err(Error::InvalidRequest);
    }
    validate_sub(request.sub).map_err(|_| Error::InvalidRequest)?;
    embedding_shares::validate_recipients(std::slice::from_ref(request.custody_key))
        .map_err(|_| Error::InvalidRequest)
}

impl State {
    /// Runs on an enclave blocking thread; holds the existing processing permit
    /// until extraction, attestation and custody encryption all finish.
    ///
    /// # Errors
    /// Reject invalid inputs, worker contention, failed extraction or unavailable
    /// attestation or custody encryption. No partial enrollment is returned.
    pub fn prepare_enrollment(
        &self,
        request: CaptureRequest<'_>,
        context: &TrustedContext,
        attestor: &dyn CaptureAttestor,
    ) -> Result<PreparedEnrollment, Error> {
        validate(&request)?;
        let _permit = self.processing.try_acquire().map_err(|_| Error::Busy)?;
        self.produce(&request, context, attestor)
    }

    /// Serves one sealed enrollment request. The caller holds the processing permit.
    /// Invalid input and rejected captures become a sealed failure for the browser;
    /// a missing capability or an internal failure is a transport-level `Unavailable`.
    pub(crate) fn enroll_sealed(
        &self,
        request: &EnrollmentRequest,
    ) -> Result<EnrollmentResult, EnclaveError> {
        let producer = self.enrollment.as_ref().ok_or(EnclaveError::Unavailable)?;
        let key: [u8; 32] = request
            .custody_public_key
            .as_slice()
            .try_into()
            .map_err(|_| EnclaveError::InvalidMessage)?;
        let custody_key = PublicKey::from(key);
        let capture = CaptureRequest {
            image_png: &request.image,
            sub: &request.sub,
            custody_key: &custody_key,
        };
        let prepared = match validate(&capture)
            .and_then(|()| self.produce(&capture, &producer.context, producer.attestor.as_ref()))
        {
            Ok(prepared) => prepared,
            Err(Error::InvalidRequest) => {
                return Ok(EnrollmentResult::Failed {
                    reason: Failure::InvalidRequest,
                });
            }
            Err(Error::Capture(reason)) => return Ok(EnrollmentResult::Failed { reason }),
            Err(Error::Busy | Error::Unavailable) => return Err(EnclaveError::Unavailable),
        };
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
            .map_err(|_| EnclaveError::Unavailable)?;
        Ok(EnrollmentResult::Success {
            enrollment: EnrollmentBundle {
                fields,
                attestation_header: prepared.attestation_header,
                encrypted_custody: prepared.encrypted_custody,
            },
        })
    }

    /// Extracts, assembles, attests and seals custody. The caller holds the permit.
    fn produce(
        &self,
        request: &CaptureRequest<'_>,
        context: &TrustedContext,
        attestor: &dyn CaptureAttestor,
    ) -> Result<PreparedEnrollment, Error> {
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
        let inputs = Inputs {
            capture: Capture {
                capture_id,
                captured_at,
                image_png: request.image_png,
                embedding: &embedding,
            },
            sub: request.sub,
            pcp_version: "1",
            recipient_keys: &context.recipient_keys,
            worker_sha384: &context.worker_sha384,
        };
        let enrollment = assemble(&inputs, attestor, &mut OsRng).map_err(|_| Error::Unavailable)?;
        let encrypted_custody = custody::encrypt(&enrollment, request.custody_key, &mut OsRng)
            .map_err(|_| Error::Unavailable)?;
        let attestation_header = enrollment.attestation_header();
        Ok(PreparedEnrollment {
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
        )
        .unwrap()
    }
    fn request(key: &PublicKey) -> CaptureRequest<'_> {
        CaptureRequest {
            image_png: b"\x89PNG\r\n\x1a\nfixture",
            sub: "0x1f",
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
        assert_eq!(prepared.form.contract_version, "2");
        assert_eq!(prepared.form.sub, "0x1f");
        // The v4 challenge and proof never reach the enclave; the browser adds them.
        assert_eq!(prepared.form.parts().len(), 12);
        assert!(prepared.form.timestamp.parse::<u64>().unwrap() >= before);
        assert!(!Uuid::parse_str(&prepared.form.capture_id).unwrap().is_nil());
        assert_eq!(
            *attestor.nonce.lock().unwrap(),
            binding_digest(&prepared.form).unwrap()
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
    fn malformed_subjects_fail_before_acquiring_a_slot_or_running_extraction() {
        struct NeverExtract;
        impl crate::engine::Engine for NeverExtract {
            fn extract(&self, _: &[u8]) -> Result<Result<FaceEmbedding, Failure>, EnclaveError> {
                panic!("malformed subjects must not reach extraction");
            }
            fn check_health(&self) -> Result<(), EnclaveError> {
                Ok(())
            }
        }
        let state = State::new(Arc::new(BootAttestor), Box::new(NeverExtract)).unwrap();
        let key = SecretKey::generate(&mut OsRng).public_key();
        let attestor = Attestor::default();
        let context = context();
        let oversized_sub = "a".repeat(129);

        // Repeat with the slot occupied: invalid inputs must not be reported as Busy.
        for busy in [false, true] {
            let _permit = busy.then(|| state.processing.try_acquire().unwrap());
            // Non-canonical subjects, including a padded field element, are never attested.
            for sub in [
                "",
                "0x1f\r\n",
                "0x 1f",
                "é",
                "0x0",
                "0x01f",
                "0x1F",
                "0x000000000000000000000000000000000000000000000000000000000000001f",
                oversized_sub.as_str(),
            ] {
                let mut input = request(&key);
                input.sub = sub;
                assert!(matches!(
                    state.prepare_enrollment(input, &context, &attestor),
                    Err(Error::InvalidRequest)
                ));
            }
        }
        assert_eq!(attestor.calls.load(Ordering::SeqCst), 0);
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
