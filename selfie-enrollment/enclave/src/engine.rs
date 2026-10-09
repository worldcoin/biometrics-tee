//! Typed adapter over the shared byte-oriented sandbox. Only VanillaSelfie extraction is exposed.
use biometric_engines_protocol::{self as protocol, failure::Kind, response::Outcome};
use selfie_enrollment_enclave_types::Error;
use selfie_enrollment_sealed_types::{Embedding, Failure, WorkerIdentity};
use zeroize::Zeroize;
pub trait Engine: Send {
    fn extract(
        &mut self,
        image: &[u8],
        identity: &WorkerIdentity,
    ) -> Result<Result<Embedding, Failure>, Error>;
    fn check_health(&self) -> Result<(), Error>;
}

/// A protocol error is terminal; a validated image/quality failure is recoverable.
pub fn decode_result(
    bytes: &[u8],
    expected_id: u64,
    identity: &WorkerIdentity,
) -> Result<Result<Embedding, Failure>, Error> {
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
            Ok(Ok(Embedding {
                vector: result.vector,
                embedding_type: result.r#type,
                version: result.version,
                inference_backend: result.inference_backend,
                worker: identity.clone(),
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
    pub worker: biometrics_sandbox::Worker,
    pub next_id: u64,
}
#[cfg(target_os = "linux")]
impl Engine for SandboxEngine {
    fn extract(
        &mut self,
        image: &[u8],
        identity: &WorkerIdentity,
    ) -> Result<Result<Embedding, Failure>, Error> {
        use protocol::{
            face::{EmbeddingRequest, FaceImage, face_image::Source},
            request::Operation,
        };
        if image.is_empty() || image.len() > selfie_enrollment_api_types::MAX_IMAGE_BYTES {
            return Ok(Err(Failure::InvalidRequest));
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .filter(|_| id != 0)
            .unwrap_or_else(|| self.worker.fail());
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
        let response = zeroize::Zeroizing::new(
            self.worker
                .exchange(&encoded)
                .unwrap_or_else(|_| self.worker.fail()),
        );
        decode_result(&response, id, identity).or_else(|_| self.worker.fail())
    }
    fn check_health(&self) -> Result<(), Error> {
        self.worker.check_alive();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_response_must_match_id_and_operation() {
        let identity = WorkerIdentity {
            profile: selfie_enrollment_api_types::PROFILE.into(),
            executable_sha384: "a".repeat(96),
        };
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
        assert!(decode_result(&response, 1, &identity).unwrap().is_ok());
        assert!(decode_result(&response, 2, &identity).is_err());
        let wrong = protocol::protobuf::encode_response(&protocol::Response::new(
            1,
            Outcome::GrayBadge(protocol::face::GrayBadgeResult {
                similarity_live_challenge: Some(1.0),
                debug_report: None,
            }),
        ));
        assert!(decode_result(&wrong, 1, &identity).is_err());
    }
}
