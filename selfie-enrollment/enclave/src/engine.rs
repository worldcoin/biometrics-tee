//! Typed embedding adapter for single-image extraction and PoseGuard enrollment batches.
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
                let code = FailureCode::try_from(failure.code).map_err(|_| Error::Unavailable)?;
                let reason = match (code, failure.pose_guard_challenge_index) {
                    (FailureCode::InvalidImage, Some(index)) => Failure::Challenge {
                        index,
                        reason: ChallengeFailure::InvalidImage,
                    },
                    (FailureCode::TemplateFailed, Some(index)) => Failure::Challenge {
                        index,
                        reason: ChallengeFailure::ExtractionFailed,
                    },
                    (FailureCode::ValidationFailed, Some(index)) => {
                        let reason = failure
                            .validation_failure
                            .as_ref()
                            .map(|details| details.reason);
                        let reason = match reason {
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
                        };
                        Failure::Challenge { index, reason }
                    }
                    (FailureCode::InvalidImage, None) => Failure::InvalidImage,
                    (FailureCode::ValidationFailed, None) => Failure::QualityRejected,
                    (FailureCode::TemplateFailed, None) => Failure::ExtractionFailed,
                    (FailureCode::InvalidRequest, _) => Failure::InvalidRequest,
                    _ => return Err(Error::Unavailable),
                };
                Ok(Err(reason))
            }
            _ => Err(Error::Unavailable),
        },
        _ => Err(Error::Unavailable),
    }
}

// Only these two sources are exposed by this enclave. The shared request guard erases
// the protobuf's owned copies even when encoding or validation fails.
#[cfg(any(target_os = "linux", test))]
fn encode_request(id: u64, image: &FaceImage) -> Result<zeroize::Zeroizing<Vec<u8>>, Failure> {
    use protocol::{face::EmbeddingRequest, request::Operation};
    use selfie_enrollment_api_types::{
        MAX_BATCH_IMAGE_BYTES, MAX_IMAGE_BYTES, POSEGUARD_CHALLENGE_COUNT,
    };
    let images: Vec<&[u8]> = match image.source.as_ref() {
        Some(Source::VanillaSelfie(bytes)) => vec![bytes],
        Some(Source::PoseGuard(capture))
            if capture.challenges.len() == POSEGUARD_CHALLENGE_COUNT =>
        {
            std::iter::once(capture.central_image.as_slice())
                .chain(capture.challenges.iter().map(|c| c.image.as_slice()))
                .collect()
        }
        _ => return Err(Failure::InvalidRequest),
    };
    if images
        .iter()
        .any(|image| image.is_empty() || image.len() > MAX_IMAGE_BYTES)
        || images.iter().map(|image| image.len()).sum::<usize>() > MAX_BATCH_IMAGE_BYTES
    {
        return Err(Failure::InvalidRequest);
    }
    let request = SensitiveRequest(protocol::Request::new(
        id,
        Operation::Embedding(EmbeddingRequest {
            image: Some(image.clone()),
        }),
    ));
    Ok(zeroize::Zeroizing::new(protocol::protobuf::encode_request(
        &request.0,
    )))
}
#[cfg(any(target_os = "linux", test))]
struct SensitiveRequest(protocol::Request);
#[cfg(any(target_os = "linux", test))]
impl Drop for SensitiveRequest {
    fn drop(&mut self) {
        if let Some(protocol::request::Operation::Embedding(request)) = &mut self.0.operation
            && let Some(image) = &mut request.image
        {
            erase_image(image);
        }
    }
}
pub(crate) fn erase_image(image: &mut FaceImage) {
    match image.source.as_mut() {
        Some(Source::VanillaSelfie(bytes) | Source::Orb(bytes) | Source::Rtms(bytes)) => {
            bytes.zeroize()
        }
        Some(Source::LightGuard(pair)) => {
            pair.illuminated.zeroize();
            pair.unilluminated.zeroize();
        }
        Some(Source::PoseGuard(capture)) => {
            capture.central_image.zeroize();
            for challenge in &mut capture.challenges {
                challenge.image.zeroize();
            }
        }
        None => {}
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_encoder_preserves_all_images_and_targets_in_one_embedding_operation() {
        use protocol::{
            face::{PoseGuard, PoseGuardCapture},
            request::Operation,
        };
        let image = FaceImage {
            source: Some(Source::PoseGuard(PoseGuard {
                central_image: vec![10],
                challenges: (0..3)
                    .map(|i| PoseGuardCapture {
                        image: vec![i + 1],
                        target_pitch: 12.0 + f32::from(i),
                        target_yaw: -23.0 - f32::from(i),
                    })
                    .collect(),
            })),
        };
        let request =
            protocol::protobuf::decode_request(&encode_request(1, &image).unwrap()).unwrap();
        let Some(Operation::Embedding(request)) = request.operation else {
            panic!("expected embedding request")
        };
        assert_eq!(request.image.as_ref(), Some(&image));
        let mut invalid = image.clone();
        let Some(Source::PoseGuard(capture)) = &mut invalid.source else {
            unreachable!()
        };
        capture.challenges.pop();
        assert!(matches!(
            encode_request(2, &invalid),
            Err(Failure::InvalidRequest)
        ));
        let vanilla = FaceImage {
            source: Some(Source::VanillaSelfie(vec![1])),
        };
        assert!(encode_request(3, &vanilla).is_ok());
    }

    #[test]
    fn indexed_worker_rejections_are_recoverable_and_malformed_indexes_are_terminal() {
        use protocol::face::{
            Failure as WorkerFailure, ImageRole, ValidationReason, ValidationTarget,
        };
        for index in 0..3 {
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
                let failure =
                    WorkerFailure::validation(reason, ValidationTarget::PoseGuardChallenge)
                        .at_image(ImageRole::EmbeddingInput)
                        .at_pose_guard_challenge(index);
                let bytes = protocol::protobuf::encode_response(&protocol::Response::new(
                    1,
                    Outcome::Failure(failure.into()),
                ));
                assert!(
                    matches!(decode_result(&bytes, 1), Ok(Err(Failure::Challenge { index: actual, reason })) if actual == index && reason == expected)
                );
            }
        }
        let failure = WorkerFailure::validation(
            ValidationReason::PoseGuardTargetMismatch,
            ValidationTarget::PoseGuardChallenge,
        )
        .at_image(ImageRole::EmbeddingInput)
        .at_pose_guard_challenge(3);
        let bytes = protocol::protobuf::encode_response(&protocol::Response::new(
            1,
            Outcome::Failure(failure.into()),
        ));
        assert!(decode_result(&bytes, 1).is_err());
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
