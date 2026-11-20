//! Typed embedding adapter over the shared byte-oriented sandbox.
use biometric_engines_protocol::{
    self as protocol,
    face::{FaceImage, face_image::Source},
    failure::Kind,
    response::Outcome,
};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{ChallengeFailure, FaceEmbedding, Failure};
use zeroize::Zeroize;
/// Serializes its own requests; health checks must not wait for an in-flight one.
pub trait Engine: Send + Sync {
    fn extract(&self, image: &FaceImage) -> Result<Result<FaceEmbedding, Failure>, Error>;
    fn check_health(&self) -> Result<(), Error>;
}

/// A protocol error is terminal; a validated image/quality failure is recoverable.
pub fn decode_result(
    bytes: &[u8],
    expected_id: u64,
) -> Result<Result<FaceEmbedding, Failure>, Error> {
    let response = protocol::protobuf::decode_response(bytes).map_err(|_| Error::Unavailable)?;
    if expected_id == 0 || response.request_id != expected_id {
        return Err(Error::Unavailable);
    }
    match response.outcome.ok_or(Error::Unavailable)? {
        Outcome::Embedding(mut result) => {
            if let Some(report) = result.debug_report.as_mut() {
                report.zeroize();
            }
            if result.vector.is_empty()
                || result.vector.len() > 4096
                || result.r#type.is_empty()
                || result.r#type.len() > 128
                || result.version.is_empty()
                || result.version.len() > 128
                || result.inference_backend.is_empty()
                || result.inference_backend.len() > 128
            {
                result.vector.zeroize();
                return Err(Error::Unavailable);
            }
            Ok(Ok(FaceEmbedding {
                embedding: result.vector,
                embedding_type: result.r#type,
                embedding_version: result.version,
                embedding_inference_backend: result.inference_backend,
            }))
        }
        Outcome::Failure(failure) => match failure.kind {
            Some(Kind::Face(mut failure)) => {
                if let Some(report) = failure.debug_report.as_mut() {
                    report.zeroize();
                }
                use protocol::face::{FailureCode, ValidationReason};
                if let Some(index) = failure.pose_guard_challenge_index {
                    let reason = match FailureCode::try_from(failure.code)
                        .map_err(|_| Error::Unavailable)?
                    {
                        FailureCode::InvalidImage => ChallengeFailure::InvalidImage,
                        FailureCode::TemplateFailed => ChallengeFailure::ExtractionFailed,
                        FailureCode::ValidationFailed => match failure
                            .validation_failure
                            .as_ref()
                            .map(|details| details.reason)
                        {
                            Some(reason)
                                if reason == ValidationReason::PoseGuardTargetMismatch as i32 =>
                            {
                                ChallengeFailure::PoseMismatch
                            }
                            Some(reason)
                                if reason == ValidationReason::PoseGuardIdentityMismatch as i32 =>
                            {
                                ChallengeFailure::IdentityMismatch
                            }
                            _ => ChallengeFailure::QualityRejected,
                        },
                        _ => return Err(Error::Unavailable),
                    };
                    return Ok(Err(Failure::Challenge { index, reason }));
                }
                let reason =
                    match FailureCode::try_from(failure.code).map_err(|_| Error::Unavailable)? {
                        FailureCode::InvalidImage => Failure::InvalidImage,
                        FailureCode::ValidationFailed => Failure::QualityRejected,
                        FailureCode::TemplateFailed => Failure::ExtractionFailed,
                        _ => return Err(Error::Unavailable),
                    };
                Ok(Err(reason))
            }
            _ => Err(Error::Unavailable),
        },
        _ => Err(Error::Unavailable),
    }
}

#[cfg(target_os = "linux")]
pub struct SandboxEngine {
    worker: std::sync::Mutex<tabernaculum::Worker>,
    /// Only read and written while holding `worker`.
    next_id: std::sync::atomic::AtomicU64,
}
#[cfg(target_os = "linux")]
impl SandboxEngine {
    #[must_use]
    pub fn new(worker: tabernaculum::Worker) -> Self {
        Self {
            worker: std::sync::Mutex::new(worker),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }
}
#[cfg(target_os = "linux")]
impl Engine for SandboxEngine {
    fn extract(&self, image: &FaceImage) -> Result<Result<FaceEmbedding, Failure>, Error> {
        use std::sync::atomic::Ordering;
        // A poisoned lock means a request panicked mid-exchange; the worker state is unknown.
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner().fail());
        let id = self.next_id.load(Ordering::Relaxed);
        let next_id = id
            .checked_add(1)
            .filter(|_| id != 0)
            .unwrap_or_else(|| worker.fail());
        self.next_id.store(next_id, Ordering::Relaxed);
        let encoded = match encode_request(id, image) {
            Ok(encoded) => encoded,
            Err(reason) => return Ok(Err(reason)),
        };
        let response = match worker.exchange(&encoded) {
            Ok(response) => zeroize::Zeroizing::new(response),
            // Nothing was sent, so the worker stays trusted and the request alone fails.
            Err(tabernaculum::ConnectionError::InvalidRequest) => {
                tracing::warn!(
                    dependency = "worker",
                    bytes = encoded.len(),
                    "worker request rejected before sending"
                );
                return Ok(Err(Failure::InvalidRequest));
            }
            Err(_) => worker.fail(),
        };
        decode_result(&response, id).or_else(|_| worker.fail())
    }
    /// Skips the check while a request runs; that request reports a dead worker itself.
    fn check_health(&self) -> Result<(), Error> {
        tabernaculum::check_alive_if_idle(&self.worker);
        Ok(())
    }
}
#[cfg(any(target_os = "linux", test))]
fn encode_request(id: u64, image: &FaceImage) -> Result<zeroize::Zeroizing<Vec<u8>>, Failure> {
    use protocol::{face::EmbeddingRequest, request::Operation};
    use selfie_enrollment_api_types::{MAX_IMAGE_BYTES, POSEGUARD_CHALLENGE_COUNT};
    let valid_image = |bytes: &[u8]| !bytes.is_empty() && bytes.len() <= MAX_IMAGE_BYTES;
    let valid = match image.source.as_ref() {
        Some(Source::VanillaSelfie(bytes)) => valid_image(bytes),
        Some(Source::PoseGuard(capture)) => {
            valid_image(&capture.central_image)
                && capture.challenges.len() == POSEGUARD_CHALLENGE_COUNT
                && capture.challenges.iter().all(|c| {
                    valid_image(&c.image)
                        && (-20.0..=20.0).contains(&c.target_pitch)
                        && (-35.0..=35.0).contains(&c.target_yaw)
                })
        }
        _ => false,
    };
    if !valid {
        return Err(Failure::InvalidRequest);
    }
    let mut request = protocol::Request::new(
        id,
        Operation::Embedding(EmbeddingRequest {
            image: Some(image.clone()),
        }),
    );
    let encoded = zeroize::Zeroizing::new(protocol::protobuf::encode_request(&request));
    if let Some(Operation::Embedding(request)) = &mut request.operation
        && let Some(image) = &mut request.image
    {
        erase_image(image);
    }
    Ok(encoded)
}

pub(crate) fn erase_image(image: &mut FaceImage) {
    match image.source.as_mut() {
        Some(Source::VanillaSelfie(bytes)) => bytes.zeroize(),
        Some(Source::PoseGuard(capture)) => {
            capture.central_image.zeroize();
            for challenge in &mut capture.challenges {
                challenge.image.zeroize();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_uses_one_embedding_request_and_reports_the_failing_capture() {
        use protocol::{
            face::{
                Failure as WorkerFailure, ImageRole, PoseGuard, PoseGuardCapture, ValidationReason,
                ValidationTarget,
            },
            request::Operation,
        };
        let image = FaceImage {
            source: Some(Source::PoseGuard(PoseGuard {
                central_image: vec![1],
                challenges: (0..3)
                    .map(|i| PoseGuardCapture {
                        image: vec![i + 2],
                        target_pitch: 10.0,
                        target_yaw: -20.0,
                    })
                    .collect(),
            })),
        };
        let request =
            protocol::protobuf::decode_request(&encode_request(1, &image).unwrap()).unwrap();
        let Some(Operation::Embedding(request)) = request.operation else {
            panic!("expected embedding")
        };
        assert_eq!(request.image.as_ref(), Some(&image));
        for (reason, expected) in [
            (
                ValidationReason::PoseGuardTargetMismatch,
                ChallengeFailure::PoseMismatch,
            ),
            (
                ValidationReason::PoseGuardIdentityMismatch,
                ChallengeFailure::IdentityMismatch,
            ),
        ] {
            let failure = WorkerFailure::validation(reason, ValidationTarget::PoseGuardChallenge)
                .at_image(ImageRole::EmbeddingInput)
                .at_pose_guard_challenge(2);
            let encoded = protocol::protobuf::encode_response(&protocol::Response::new(
                1,
                Outcome::Failure(failure.into()),
            ));
            assert!(
                matches!(decode_result(&encoded, 1), Ok(Err(Failure::Challenge { index: 2, reason })) if reason == expected)
            );
        }
    }
    #[test]
    fn worker_response_must_match_id_and_operation() {
        let result = protocol::face::EmbeddingResult {
            vector: "AA==".into(),
            r#type: "face".into(),
            version: "1".into(),
            inference_backend: "cpu".into(),
            debug_report: None,
        };
        let response = protocol::protobuf::encode_response(&protocol::Response::new(
            1,
            Outcome::Embedding(result),
        ));
        assert!(decode_result(&response, 1).unwrap().is_ok());
        assert!(decode_result(&response, 2).is_err());
        let wrong = protocol::protobuf::encode_response(&protocol::Response::new(
            1,
            Outcome::GrayBadge(protocol::face::GrayBadgeResult {
                similarity_live_challenge: Some(1.0),
                debug_report: None,
            }),
        ));
        assert!(decode_result(&wrong, 1).is_err());
    }
}
