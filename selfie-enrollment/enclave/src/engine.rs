//! Typed adapter over the shared byte-oriented sandbox. Vanilla extraction and optional PoseGuard shadow evaluation.
use biometric_engines_protocol::{self as protocol, failure::Kind, response::Outcome};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{
    FaceEmbedding, Failure,
    poseguard::{PoseTarget, Rejection},
};
use zeroize::Zeroize;
/// Serializes its own requests; health checks must not wait for an in-flight one.
pub trait Engine: Send + Sync {
    fn extract(&self, image: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error>;
    fn check_health(&self) -> Result<(), Error>;
    fn supports_poseguard(&self) -> bool {
        false
    }
    fn evaluate_pose(
        &self,
        _image: &[u8],
        _target: Option<PoseTarget>,
        _reference: Option<&FaceEmbedding>,
    ) -> Result<PoseEvaluation, Error> {
        Err(Error::Unavailable)
    }
}

pub enum PoseEvaluation {
    Identity(FaceEmbedding),
    Similarity(f64),
    Rejected { reason: Rejection, retryable: bool },
}

fn embedding(mut result: protocol::face::EmbeddingResult) -> Result<FaceEmbedding, Error> {
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
    Ok(FaceEmbedding {
        embedding: result.vector,
        embedding_type: result.r#type,
        embedding_version: result.version,
        embedding_inference_backend: result.inference_backend,
    })
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
        Outcome::Embedding(result) => embedding(result).map(Ok),
        Outcome::Failure(failure) => match failure.kind {
            Some(Kind::Face(mut failure)) => {
                if let Some(report) = failure.debug_report.as_mut() {
                    report.zeroize();
                }
                use protocol::face::FailureCode;
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

pub fn decode_pose_result(bytes: &[u8], expected_id: u64) -> Result<PoseEvaluation, Error> {
    use protocol::face::{
        FailureCode, ValidationReason, pose_guard_result::Outcome as PoseOutcome,
    };
    let response = protocol::protobuf::decode_response(bytes).map_err(|_| Error::Unavailable)?;
    if expected_id == 0 || response.request_id != expected_id {
        return Err(Error::Unavailable);
    }
    let Some(Outcome::PoseGuard(result)) = response.outcome else {
        return Err(Error::Unavailable);
    };
    match result.outcome.ok_or(Error::Unavailable)? {
        PoseOutcome::Identity(result) => embedding(result).map(PoseEvaluation::Identity),
        PoseOutcome::Similarity(score) if score.is_finite() && (-1.0..=1.0).contains(&score) => {
            Ok(PoseEvaluation::Similarity(score))
        }
        PoseOutcome::Rejection(rejection) => {
            let mut failure = rejection.failure.ok_or(Error::Unavailable)?;
            if let Some(report) = failure.debug_report.as_mut() {
                report.zeroize();
            }
            let reason =
                match FailureCode::try_from(failure.code).map_err(|_| Error::Unavailable)? {
                    FailureCode::InvalidImage => Rejection::InvalidImage,
                    FailureCode::ValidationFailed => {
                        let validation = failure.validation_failure.ok_or(Error::Unavailable)?;
                        match ValidationReason::try_from(validation.reason)
                            .map_err(|_| Error::Unavailable)?
                        {
                            ValidationReason::PoseGuardTargetMismatch => Rejection::PoseMismatch,
                            ValidationReason::SpoofDetected
                            | ValidationReason::DepthSpoofDetected
                            | ValidationReason::ThermalSpoofDetected => Rejection::AnalysisFailed,
                            _ => Rejection::QualityRejected,
                        }
                    }
                    FailureCode::TemplateFailed | FailureCode::MatchingFailed => {
                        Rejection::AnalysisFailed
                    }
                    _ => return Err(Error::Unavailable),
                };
            if rejection.retryable
                && !matches!(
                    reason,
                    Rejection::InvalidImage | Rejection::QualityRejected | Rejection::PoseMismatch
                )
            {
                return Err(Error::Unavailable);
            }
            Ok(PoseEvaluation::Rejected {
                reason,
                retryable: rejection.retryable,
            })
        }
        _ => Err(Error::Unavailable),
    }
}

#[cfg(target_os = "linux")]
pub struct SandboxEngine {
    worker: std::sync::Mutex<tabernaculum::Worker>,
    /// Only read and written while holding `worker`.
    next_id: std::sync::atomic::AtomicU64,
    supports_poseguard: bool,
}
#[cfg(target_os = "linux")]
impl SandboxEngine {
    #[must_use]
    pub fn new(worker: tabernaculum::Worker, supports_poseguard: bool) -> Self {
        Self {
            worker: std::sync::Mutex::new(worker),
            next_id: std::sync::atomic::AtomicU64::new(1),
            supports_poseguard,
        }
    }
}
#[cfg(target_os = "linux")]
impl Engine for SandboxEngine {
    fn extract(&self, image: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error> {
        if image.is_empty() || image.len() > selfie_enrollment_api_types::MAX_IMAGE_BYTES {
            return Ok(Err(Failure::InvalidRequest));
        }
        match self.exchange(
            protocol::request::Operation::Embedding(protocol::face::EmbeddingRequest {
                image: Some(protocol::face::FaceImage {
                    source: Some(protocol::face::face_image::Source::VanillaSelfie(
                        image.to_vec(),
                    )),
                }),
            }),
            decode_result,
        ) {
            // Preserve the vanilla failure response when the worker sends nothing.
            Err(Error::InvalidMessage) => Ok(Err(Failure::InvalidRequest)),
            result => result,
        }
    }
    fn supports_poseguard(&self) -> bool {
        self.supports_poseguard
    }
    fn evaluate_pose(
        &self,
        image: &[u8],
        target: Option<PoseTarget>,
        reference: Option<&FaceEmbedding>,
    ) -> Result<PoseEvaluation, Error> {
        if !self.supports_poseguard {
            return Err(Error::Unavailable);
        }
        if image.is_empty() || image.len() > selfie_enrollment_api_types::MAX_IMAGE_BYTES {
            return Ok(PoseEvaluation::Rejected {
                reason: Rejection::InvalidImage,
                retryable: true,
            });
        }
        self.exchange(
            protocol::request::Operation::PoseGuard(protocol::face::PoseGuardRequest {
                image: image.to_vec(),
                target: target.map(|t| protocol::face::PoseGuardTarget {
                    pitch: f32::from(t.pitch),
                    yaw: f32::from(t.yaw),
                }),
                reference: reference.map(|e| protocol::face::EmbeddingResult {
                    vector: e.embedding.clone(),
                    r#type: e.embedding_type.clone(),
                    version: e.embedding_version.clone(),
                    inference_backend: e.embedding_inference_backend.clone(),
                    debug_report: None,
                }),
            }),
            decode_pose_result,
        )
    }
    /// Skips the check while a request runs; that request reports a dead worker itself.
    fn check_health(&self) -> Result<(), Error> {
        tabernaculum::check_alive_if_idle(&self.worker);
        Ok(())
    }
}
#[cfg(target_os = "linux")]
impl SandboxEngine {
    fn exchange<T>(
        &self,
        operation: protocol::request::Operation,
        decode: impl FnOnce(&[u8], u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        use protocol::{
            face::{FaceImage, face_image::Source},
            request::Operation,
        };
        use std::sync::atomic::Ordering;
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner().fail());
        let id = self.next_id.load(Ordering::Relaxed);
        let next = id
            .checked_add(1)
            .filter(|_| id != 0)
            .unwrap_or_else(|| worker.fail());
        self.next_id.store(next, Ordering::Relaxed);
        let mut request = protocol::Request::new(id, operation);
        let encoded = zeroize::Zeroizing::new(protocol::protobuf::encode_request(&request));
        match request.operation.as_mut() {
            Some(Operation::Embedding(r)) => {
                if let Some(FaceImage {
                    source: Some(Source::VanillaSelfie(bytes)),
                }) = r.image.as_mut()
                {
                    bytes.zeroize();
                }
            }
            Some(Operation::PoseGuard(r)) => {
                r.image.zeroize();
                if let Some(reference) = r.reference.as_mut() {
                    reference.vector.zeroize();
                }
            }
            _ => {}
        }
        let response = match worker.exchange(&encoded) {
            Ok(response) => zeroize::Zeroizing::new(response),
            Err(tabernaculum::ConnectionError::InvalidRequest) => {
                tracing::warn!(
                    dependency = "worker",
                    bytes = encoded.len(),
                    "worker request rejected before sending"
                );
                return Err(Error::InvalidMessage);
            }
            Err(_) => worker.fail(),
        };
        decode(&response, id).or_else(|_| worker.fail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(decode_pose_result(&response, 1).is_err());
    }

    #[test]
    fn pose_results_preserve_scores_retries_and_terminal_failures() {
        use protocol::face::{
            Failure as WorkerFailure, FailureCode, PoseGuardRejection, PoseGuardResult,
            ValidationReason, ValidationTarget, pose_guard_result::Outcome as PoseOutcome,
        };
        let encode = |outcome| {
            protocol::protobuf::encode_response(&protocol::Response::new(
                7,
                Outcome::PoseGuard(PoseGuardResult {
                    outcome: Some(outcome),
                }),
            ))
        };
        let score = encode(PoseOutcome::Similarity(0.4));
        assert!(matches!(
            decode_pose_result(&score, 7).unwrap(),
            PoseEvaluation::Similarity(0.4)
        ));
        assert!(decode_pose_result(&score, 8).is_err());
        assert!(decode_result(&score, 7).is_err());
        for invalid in [f64::NAN, f64::INFINITY, 1.01, -1.01] {
            assert!(decode_pose_result(&encode(PoseOutcome::Similarity(invalid)), 7).is_err());
        }
        for (failure, expected, retryable) in [
            (
                WorkerFailure::validation(
                    ValidationReason::PoseGuardTargetMismatch,
                    ValidationTarget::Image,
                ),
                Rejection::PoseMismatch,
                true,
            ),
            (
                WorkerFailure::new(FailureCode::InvalidImage),
                Rejection::InvalidImage,
                true,
            ),
            (
                WorkerFailure::new(FailureCode::TemplateFailed),
                Rejection::AnalysisFailed,
                false,
            ),
        ] {
            let reply = encode(PoseOutcome::Rejection(PoseGuardRejection {
                failure: Some(failure.at_image(protocol::face::ImageRole::Challenge)),
                retryable,
            }));
            assert!(matches!(
                decode_pose_result(&reply, 7).unwrap(),
                PoseEvaluation::Rejected { reason, retryable: actual }
                    if reason == expected && actual == retryable
            ));
        }
    }
}
