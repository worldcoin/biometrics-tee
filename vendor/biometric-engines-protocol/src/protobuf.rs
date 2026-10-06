//! Bounded protobuf codecs over the public generated messages.
use crate::{
    EmptyReason, Failure, PROTOCOL_VERSION, Ready, Request, Response,
    face::{
        self, ComparisonRole, FailureCode, ImageRole, ValidationReason, ValidationTarget,
        failure::Location,
    },
    failure::Kind,
    framing, migration,
    protocol_failure::Reason,
    request::Operation,
    response::Outcome,
};
use prost::Message;

/// A request rejected before reaching the worker.
///
/// `request_id` is the reserved zero for oversized or malformed bytes, which have no
/// trustworthy request ID, and the decoded ID for requests exceeding the face image limits.
#[derive(Debug, thiserror::Error)]
#[error("request was rejected: {failure}")]
pub struct RejectedRequest {
    pub request_id: u64,
    #[source]
    pub failure: Failure,
}

/// Encodes startup completion using the same framing as regular messages.
#[must_use]
pub fn encode_ready() -> Vec<u8> {
    Ready {
        protocol_version: PROTOCOL_VERSION,
    }
    .encode_to_vec()
}

/// Checks the initialization acknowledgment before the client becomes usable.
#[must_use]
pub fn decode_ready(bytes: &[u8]) -> bool {
    Ready::decode(bytes).is_ok_and(|ready| ready.protocol_version == PROTOCOL_VERSION)
}

/// Encodes the generated request.
#[must_use]
pub fn encode_request(request: &Request) -> Vec<u8> {
    request.encode_to_vec()
}

/// Decodes the protobuf structure and enforces [`face::check_image_limits`] or
/// [`migration::check_image_limits`] for requests of the current protocol version.
///
/// # Errors
/// Rejects oversized or malformed protobuf bytes with request ID zero, and requests
/// exceeding the image limits with their decoded request ID.
pub fn decode_request(bytes: &[u8]) -> Result<Request, RejectedRequest> {
    let request = check_size(bytes)
        .and_then(|()| Request::decode(bytes).map_err(|_| malformed()))
        .map_err(|failure| RejectedRequest {
            request_id: 0,
            failure,
        })?;
    match &request.operation {
        Some(operation) if request.protocol_version == PROTOCOL_VERSION => {
            let limits = match operation {
                Operation::Migration(request) => {
                    migration::check_image_limits(request).map_err(Failure::from)
                }
                operation => face::check_image_limits(operation).map_err(Failure::from),
            };
            limits.map_err(|failure| RejectedRequest {
                request_id: request.request_id,
                failure,
            })?;
        }
        _ => {}
    }
    Ok(request)
}

/// Encodes the generated response.
#[must_use]
pub fn encode_response(response: &Response) -> Vec<u8> {
    response.encode_to_vec()
}

/// Decodes and validates a response for consumers that need checked worker results.
///
/// # Errors
/// Rejects malformed envelopes, absent/nonfinite scores, oversized face embeddings,
/// migration results with a missing part or misshaped codes or embeddings, and incomplete or
/// unrecognized failure details. No domain-type conversion is performed.
pub fn decode_response(bytes: &[u8]) -> Result<Response, Failure> {
    check_size(bytes)?;
    let response = Response::decode(bytes).map_err(|_| malformed())?;
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(Reason::UnsupportedVersion(EmptyReason {}).into());
    }
    match response.outcome.as_ref().ok_or_else(malformed)? {
        Outcome::DeepFace(result) => {
            score(result.similarity_credential_live)?;
            score(result.similarity_credential_challenge)?;
            score(result.similarity_live_challenge)?;
        }
        Outcome::GrayBadge(result) => score(result.similarity_live_challenge)?,
        Outcome::Embedding(result) => {
            if result.vector.len() > face::MAX_ENCODED_EMBEDDING_BYTES {
                return Err(malformed());
            }
        }
        Outcome::Migration(result) => check_migration_result(result)?,
        Outcome::Failure(failure) => match failure.kind.as_ref().ok_or_else(malformed)? {
            Kind::Protocol(failure) => {
                failure.reason.as_ref().ok_or_else(malformed)?;
            }
            Kind::Face(failure) => validate_face_failure(failure)?,
            Kind::Migration(failure) => validate_migration_failure(failure)?,
        },
    }
    Ok(response)
}

fn validate_face_failure(failure: &face::Failure) -> Result<(), Failure> {
    match failure.location {
        Some(Location::Image(role)) => match ImageRole::try_from(role) {
            Ok(ImageRole::Unspecified) | Err(_) => return Err(malformed()),
            _ => {}
        },
        Some(Location::Comparison(role)) => match ComparisonRole::try_from(role) {
            Ok(ComparisonRole::Unspecified) | Err(_) => return Err(malformed()),
            _ => {}
        },
        None => {}
    }
    let code = FailureCode::try_from(failure.code).map_err(|_| malformed())?;
    if code == FailureCode::Unspecified
        || (code == FailureCode::InvalidRequest) != failure.invalid_request_reason.is_some()
        || (code == FailureCode::ValidationFailed) != failure.validation_failure.is_some()
    {
        return Err(malformed());
    }
    if let Some(reason) = &failure.invalid_request_reason {
        reason.reason.as_ref().ok_or_else(malformed)?;
    }
    if let Some(details) = &failure.validation_failure {
        if !matches!(failure.location, Some(Location::Image(_)))
            || matches!(
                ValidationReason::try_from(details.reason),
                Ok(ValidationReason::Unspecified) | Err(_)
            )
            || matches!(
                ValidationTarget::try_from(details.target),
                Ok(ValidationTarget::Unspecified) | Err(_)
            )
        {
            return Err(malformed());
        }
    }
    Ok(())
}

/// Checks that the face embedding is present and bounded like [`Outcome::Embedding`], and
/// that both eyes carry v2.1-sized codes and [`migration::EMBEDDING_SIZE`] embeddings: int4
/// values in [`migration::I4_RANGE`] and finite f32 values.
fn check_migration_result(result: &migration::MigrationResult) -> Result<(), Failure> {
    let face = result.face_embedding.as_ref().ok_or_else(malformed)?;
    if face.vector.is_empty() || face.vector.len() > face::MAX_ENCODED_EMBEDDING_BYTES {
        return Err(malformed());
    }
    for eye in [&result.left_iris, &result.right_iris] {
        let eye = eye.as_ref().ok_or_else(malformed)?;
        let codes_valid = [&eye.iris_code, &eye.mask_code]
            .iter()
            .all(|code| code.len() == migration::ENCODED_CODE_LEN);
        let i4_valid = [&eye.embedding, &eye.mirror_embedding]
            .iter()
            .all(|vector| {
                vector.len() == migration::EMBEDDING_SIZE
                    && vector
                        .iter()
                        .all(|&value| migration::I4_RANGE.contains(&value.cast_signed()))
            });
        let f32_valid = [&eye.embedding_f32, &eye.mirror_embedding_f32]
            .iter()
            .all(|vector| {
                vector.len() == migration::EMBEDDING_SIZE
                    && vector.iter().all(|value| value.is_finite())
            });
        if !(codes_valid && i4_valid && f32_valid) {
            return Err(malformed());
        }
    }
    Ok(())
}

fn validate_migration_failure(failure: &migration::Failure) -> Result<(), Failure> {
    let code = migration::FailureCode::try_from(failure.code).map_err(|_| malformed())?;
    let image = migration::ImageRole::try_from(failure.image).map_err(|_| malformed())?;
    if code == migration::FailureCode::Unspecified
        || (code != migration::FailureCode::Internal && image == migration::ImageRole::Unspecified)
        || (code == migration::FailureCode::InvalidRequest)
            != failure.invalid_request_reason.is_some()
    {
        return Err(malformed());
    }
    if let Some(reason) = &failure.invalid_request_reason {
        reason.reason.as_ref().ok_or_else(malformed)?;
    }
    Ok(())
}

fn score(value: Option<f64>) -> Result<(), Failure> {
    if value.is_some_and(f64::is_finite) {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn malformed() -> Failure {
    Reason::MalformedMessage(EmptyReason {}).into()
}

fn check_size(bytes: &[u8]) -> Result<(), Failure> {
    if bytes.len() > framing::MAX_FRAME_BYTES {
        return Err(Reason::MessageTooLarge(crate::ByteLimitExceeded {
            limit_bytes: framing::MAX_FRAME_BYTES as u64,
        })
        .into());
    }
    Ok(())
}
