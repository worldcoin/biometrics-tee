//! Typed adapter over the shared byte-oriented sandbox. Only VanillaSelfie extraction is exposed.
use biometric_engines_protocol::{self as protocol, failure::Kind, response::Outcome};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{FaceEmbedding, Failure};
use zeroize::Zeroize;
/// Serializes its own requests; health checks must not wait for an in-flight one.
pub trait Engine: Send + Sync {
    fn extract(&self, image: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error>;
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
    fn extract(&self, image: &[u8]) -> Result<Result<FaceEmbedding, Failure>, Error> {
        use protocol::{
            face::{EmbeddingRequest, FaceImage, face_image::Source},
            request::Operation,
        };
        use std::sync::atomic::Ordering;
        if image.is_empty() || image.len() > selfie_enrollment_api_types::MAX_IMAGE_BYTES {
            return Ok(Err(Failure::InvalidRequest));
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
