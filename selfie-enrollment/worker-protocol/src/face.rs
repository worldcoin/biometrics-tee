//! Public generated face messages and small construction helpers.
pub use crate::generated::face::v1::*;
use crate::request::Operation;

/// Per encoded image: 16 MiB.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
/// Total encoded image bytes per request: 60 MiB.
pub const MAX_TOTAL_IMAGE_BYTES: usize = 60 * 1024 * 1024;
/// Maximum encoded embedding vector length: 4 KiB.
/// A 512-element f32 vector with a bincode length prefix uses 2,744 base64 bytes.
pub const MAX_ENCODED_EMBEDDING_BYTES: usize = 4 * 1024;

/// Checks each encoded image of `operation` against [`MAX_IMAGE_BYTES`] and their sum
/// against [`MAX_TOTAL_IMAGE_BYTES`].
///
/// # Errors
/// Returns an `ImageTooLarge` failure located at the role of the first oversized image,
/// or an operation-wide `TotalImagesTooLarge` failure without location.
pub fn check_image_limits(operation: &Operation) -> Result<(), Failure> {
    if let Operation::PoseGuard(request) = operation {
        if request.image.len() > MAX_IMAGE_BYTES {
            return Err(
                Failure::invalid(invalid_request_reason::Reason::ImageTooLarge(
                    ByteLimitExceeded {
                        limit_bytes: MAX_IMAGE_BYTES as u64,
                    },
                ))
                .at_image(if request.target.is_some() {
                    ImageRole::Challenge
                } else {
                    ImageRole::EmbeddingInput
                }),
            );
        }
        return Ok(());
    }
    let images: &[(Option<&FaceImage>, ImageRole)] = match operation {
        Operation::DeepFace(request) => &[
            (request.credential.as_ref(), ImageRole::Credential),
            (request.live.as_ref(), ImageRole::Live),
            (request.challenge.as_ref(), ImageRole::Challenge),
        ],
        Operation::GrayBadge(request) => &[
            (request.live.as_ref(), ImageRole::Live),
            (request.challenge.as_ref(), ImageRole::Challenge),
        ],
        Operation::Embedding(request) => &[(request.image.as_ref(), ImageRole::EmbeddingInput)],
        Operation::Migration(_) | Operation::PoseGuard(_) => &[],
    };

    let mut total = 0;
    for &(image, role) in images {
        let Some(source) = image.and_then(|image| image.source.as_ref()) else {
            continue;
        };
        let frames: [&[u8]; 2] = match source {
            face_image::Source::Orb(bytes)
            | face_image::Source::VanillaSelfie(bytes)
            | face_image::Source::Rtms(bytes) => [bytes, &[]],
            face_image::Source::LightGuard(pair) => [&pair.illuminated, &pair.unilluminated],
        };
        for frame in frames {
            if frame.len() > MAX_IMAGE_BYTES {
                return Err(
                    Failure::invalid(invalid_request_reason::Reason::ImageTooLarge(
                        ByteLimitExceeded {
                            limit_bytes: MAX_IMAGE_BYTES as u64,
                        },
                    ))
                    .at_image(role),
                );
            }
            total += frame.len();
        }
    }
    if total > MAX_TOTAL_IMAGE_BYTES {
        return Err(Failure::invalid(
            invalid_request_reason::Reason::TotalImagesTooLarge(ByteLimitExceeded {
                limit_bytes: MAX_TOTAL_IMAGE_BYTES as u64,
            }),
        ));
    }
    Ok(())
}

impl Failure {
    /// Create a new `Failure` carrying the provided `code`.
    ///
    /// This will lead to a barebones failure based on the `FailureCode`
    /// that matches the biometric engines protocol.
    #[must_use]
    pub fn new(code: FailureCode) -> Self {
        Self {
            code: code as i32,
            ..Self::default()
        }
    }

    /// Shorthand instantiation of a `Failure` indicating an invalid request.
    ///
    /// The `reason` is injected into the created `Failure` to give reason why
    /// the request was determined to be invalid.
    #[must_use]
    pub fn invalid(reason: invalid_request_reason::Reason) -> Self {
        Self {
            invalid_request_reason: Some(InvalidRequestReason {
                reason: Some(reason),
            }),
            ..Self::new(FailureCode::InvalidRequest)
        }
    }

    /// Shorthand instantiation of a `Failure` indicating a face image validation failure.
    ///
    /// `reason` indicates the kind of validation that was failed, e.g. no face was found.
    /// `target` indicates which image participating in the request failed the validation.
    #[must_use]
    pub fn validation(reason: ValidationReason, target: ValidationTarget) -> Self {
        Self {
            validation_failure: Some(ValidationFailure {
                reason: reason as i32,
                target: target as i32,
            }),
            ..Self::new(FailureCode::ValidationFailed)
        }
    }

    /// Indicate for which image role the failure occured.
    ///
    /// This indication is helpful to differentiate which image was causing
    /// a failure in case that a request carries multiple images.
    #[must_use]
    pub fn at_image(mut self, role: ImageRole) -> Self {
        self.location = Some(failure::Location::Image(role as i32));
        self
    }

    /// Indicate for which comparison role the failure occured.
    ///
    /// This indication is helpful to differentiate which comparison was
    /// causing a failure in case that a request performs multiple.
    #[must_use]
    pub fn at_comparison(mut self, role: ComparisonRole) -> Self {
        self.location = Some(failure::Location::Comparison(role as i32));
        self
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Failure {}

impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Failure")
            .field("code", &crate::enum_debug::<FailureCode>(self.code))
            .field("location", &self.location)
            .field("invalid_request_reason", &self.invalid_request_reason)
            .field("validation_failure", &self.validation_failure)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for failure::Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Image(role) => f
                .debug_tuple("Image")
                .field(&crate::enum_debug::<ImageRole>(role))
                .finish(),
            Self::Comparison(role) => f
                .debug_tuple("Comparison")
                .field(&crate::enum_debug::<ComparisonRole>(role))
                .finish(),
        }
    }
}

impl std::fmt::Debug for DeepFaceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepFaceResult")
            .field(
                "similarity_credential_live",
                &self.similarity_credential_live,
            )
            .field(
                "similarity_credential_challenge",
                &self.similarity_credential_challenge,
            )
            .field("similarity_live_challenge", &self.similarity_live_challenge)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GrayBadgeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrayBadgeResult")
            .field("similarity_live_challenge", &self.similarity_live_challenge)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EmbeddingResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingResult")
            .field("r#type", &self.r#type)
            .field("version", &self.version)
            .field("inference_backend", &self.inference_backend)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FaceImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaceImage")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LightGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightGuard")
            .field("matching_frame", &self.matching_frame)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for face_image::Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Orb(_) => f.debug_tuple("Orb").finish_non_exhaustive(),
            Self::VanillaSelfie(_) => f.debug_tuple("VanillaSelfie").finish_non_exhaustive(),
            Self::LightGuard(_) => f.debug_tuple("LightGuard").finish_non_exhaustive(),
            Self::Rtms(_) => f.debug_tuple("Rtms").finish_non_exhaustive(),
        }
    }
}

/// Bounds the reference metadata accepted by `PoseGuard` without interpreting its vector.
#[must_use]
pub fn valid_poseguard_embedding(embedding: &EmbeddingResult) -> bool {
    !embedding.vector.is_empty()
        && embedding.vector.len() <= MAX_ENCODED_EMBEDDING_BYTES
        && [
            &embedding.r#type,
            &embedding.version,
            &embedding.inference_backend,
        ]
        .into_iter()
        .all(|value| !value.is_empty() && value.len() <= 128)
        && embedding.debug_report.is_none()
}

/// Capture-stage failures that may be retried. Spoof and processing failures are terminal.
#[must_use]
pub fn poseguard_retryable_failure(failure: &Failure) -> bool {
    if failure.code == FailureCode::InvalidImage as i32 {
        return true;
    }
    failure.code == FailureCode::ValidationFailed as i32
        && failure.validation_failure.as_ref().is_some_and(|details| {
            matches!(ValidationReason::try_from(details.reason), Ok(reason)
                if !matches!(reason, ValidationReason::Unspecified
                    | ValidationReason::SpoofDetected | ValidationReason::DepthSpoofDetected
                    | ValidationReason::ThermalSpoofDetected | ValidationReason::LightGuardScoreTooLow
                    | ValidationReason::DepthGuardScoreTooHigh | ValidationReason::PerspectiveDistortionScoreTooLow
                    | ValidationReason::MotionGuardScoreTooHigh | ValidationReason::AgeBelowThreshold))
        })
}

impl std::fmt::Debug for PoseGuardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoseGuardRequest")
            .field("challenge", &self.target.is_some())
            .finish_non_exhaustive()
    }
}
