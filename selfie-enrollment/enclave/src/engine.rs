//! Typed adapter over the shared byte-oriented sandbox. Only VanillaSelfie extraction is exposed.
use biometric_engines_protocol::{self as protocol, failure::Kind, response::Outcome};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{DebugReport, FaceEmbedding, Failure};
use zeroize::Zeroize;
/// Serializes its own requests; health checks must not wait for an in-flight one.
pub trait Engine: Send + Sync {
    fn extract(&self, image: &[u8]) -> Result<Extraction, Error>;
    fn check_health(&self) -> Result<(), Error>;
}

/// An embedding or recoverable failure, with the worker's bounded report.
pub struct Extraction {
    pub outcome: Result<FaceEmbedding, Failure>,
    pub debug_report: DebugReport,
}

/// A protocol error is terminal; a validated image/quality failure is recoverable.
pub fn decode_result(bytes: &[u8], expected_id: u64) -> Result<Extraction, Error> {
    let response = protocol::protobuf::decode_response(bytes).map_err(|_| Error::Unavailable)?;
    let mut outcome = response.outcome.ok_or(Error::Unavailable)?;
    if expected_id == 0 || response.request_id != expected_id {
        erase(&mut outcome);
        return Err(Error::Unavailable);
    }
    match outcome {
        Outcome::Embedding(mut result) => {
            let debug_report = result.debug_report.take().into();
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
            Ok(Extraction {
                outcome: Ok(FaceEmbedding {
                    embedding: result.vector,
                    embedding_type: result.r#type,
                    embedding_version: result.version,
                    embedding_inference_backend: result.inference_backend,
                }),
                debug_report,
            })
        }
        Outcome::Failure(failure) => match failure.kind {
            Some(Kind::Face(mut failure)) => {
                let debug_report = failure.debug_report.take().into();
                use protocol::face::FailureCode;
                let reason =
                    match FailureCode::try_from(failure.code).map_err(|_| Error::Unavailable)? {
                        FailureCode::InvalidImage => Failure::InvalidImage,
                        FailureCode::ValidationFailed => Failure::QualityRejected,
                        FailureCode::TemplateFailed => Failure::ExtractionFailed,
                        _ => return Err(Error::Unavailable),
                    };
                Ok(Extraction {
                    outcome: Err(reason),
                    debug_report,
                })
            }
            _ => Err(Error::Unavailable),
        },
        mut outcome => {
            erase(&mut outcome);
            Err(Error::Unavailable)
        }
    }
}

/// Erases the vector and reports of a worker response this adapter rejects.
fn erase(outcome: &mut Outcome) {
    match outcome {
        Outcome::Embedding(result) => {
            result.vector.zeroize();
            result.debug_report.zeroize();
        }
        Outcome::DeepFace(result) => result.debug_report.zeroize(),
        Outcome::GrayBadge(result) => result.debug_report.zeroize(),
        Outcome::Failure(failure) => {
            if let Some(Kind::Face(failure)) = &mut failure.kind {
                failure.debug_report.zeroize();
            }
        }
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
    fn extract(&self, image: &[u8]) -> Result<Extraction, Error> {
        use protocol::{
            face::{EmbeddingRequest, FaceImage, face_image::Source},
            request::Operation,
        };
        use std::sync::atomic::Ordering;
        let rejected = || Extraction {
            outcome: Err(Failure::InvalidRequest),
            debug_report: DebugReport::NotProduced,
        };
        if image.is_empty() || image.len() > selfie_enrollment_api_types::MAX_IMAGE_BYTES {
            return Ok(rejected());
        }
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
        let mut request = protocol::Request::new(
            id,
            Operation::Embedding(EmbeddingRequest {
                image: Some(FaceImage {
                    source: Some(Source::VanillaSelfie(image.to_vec())),
                }),
            }),
        );
        let encoded = zeroize::Zeroizing::new(protocol::protobuf::encode_request(&request));
        if let Some(Operation::Embedding(ref mut r)) = request.operation
            && let Some(FaceImage {
                source: Some(Source::VanillaSelfie(ref mut bytes)),
            }) = r.image
        {
            bytes.zeroize();
        }
        let response = match worker.exchange(&encoded) {
            Ok(response) => zeroize::Zeroizing::new(response),
            // Nothing was sent, so the worker stays trusted and the request alone fails.
            Err(tabernaculum::ConnectionError::InvalidRequest) => {
                tracing::warn!(
                    dependency = "worker",
                    bytes = encoded.len(),
                    "worker request rejected before sending"
                );
                return Ok(rejected());
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
        let decoded = decode_result(&response, 1).unwrap();
        assert!(decoded.outcome.is_ok());
        assert_eq!(decoded.debug_report, DebugReport::NotProduced);
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
    #[test]
    fn rejected_responses_are_erased() {
        use protocol::face::{
            DeepFaceResult, EmbeddingResult, Failure as FaceFailure, FailureCode, GrayBadgeResult,
        };
        let report = || Some("private-report".to_owned());
        for mut outcome in [
            Outcome::Embedding(EmbeddingResult {
                vector: "private-vector".into(),
                debug_report: report(),
                ..Default::default()
            }),
            Outcome::DeepFace(DeepFaceResult {
                debug_report: report(),
                ..Default::default()
            }),
            Outcome::GrayBadge(GrayBadgeResult {
                debug_report: report(),
                ..Default::default()
            }),
            Outcome::Failure(
                FaceFailure {
                    debug_report: report(),
                    ..FaceFailure::new(FailureCode::InvalidImage)
                }
                .into(),
            ),
        ] {
            erase(&mut outcome);
            let bytes = protocol::protobuf::encode_response(&protocol::Response::new(1, outcome));
            assert!(!bytes.windows(7).any(|window| window == b"private"));
        }
    }
    #[test]
    fn reports_survive_success_and_recoverable_failures() {
        use protocol::face::{
            Failure as FaceFailure, FailureCode, ImageRole, ValidationReason, ValidationTarget,
        };
        let json = r#"{"diagnostic":1}"#;
        let available = DebugReport::Available { json: json.into() };
        let encode =
            |outcome| protocol::protobuf::encode_response(&protocol::Response::new(1, outcome));
        let result = protocol::face::EmbeddingResult {
            vector: "AA==".into(),
            r#type: "face".into(),
            version: "1".into(),
            inference_backend: "cpu".into(),
            debug_report: Some(json.into()),
        };
        let decoded = decode_result(&encode(Outcome::Embedding(result)), 1).unwrap();
        assert!(decoded.outcome.is_ok());
        assert_eq!(decoded.debug_report, available);
        for (failure, reason) in [
            (
                FaceFailure::new(FailureCode::InvalidImage),
                Failure::InvalidImage,
            ),
            (
                FaceFailure::validation(ValidationReason::LowQuality, ValidationTarget::Image)
                    .at_image(ImageRole::EmbeddingInput),
                Failure::QualityRejected,
            ),
            (
                FaceFailure::new(FailureCode::TemplateFailed),
                Failure::ExtractionFailed,
            ),
        ] {
            let failure = FaceFailure {
                debug_report: Some(json.into()),
                ..failure
            };
            let decoded = decode_result(&encode(Outcome::Failure(failure.into())), 1).unwrap();
            assert_eq!(decoded.outcome.err(), Some(reason));
            assert_eq!(decoded.debug_report, available);
        }
    }
}
