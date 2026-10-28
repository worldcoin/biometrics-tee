//! Public generated migration messages and small construction helpers.
pub use crate::generated::migration::v1::*;

/// Per encoded image: 16 MiB.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
/// Base64 length of a packed v2.1 iris or mask code: 16 x 200 x 2 x 2 bits, 1,600 bytes.
pub const ENCODED_CODE_LEN: usize = 2136;
/// Maximum encoded face embedding vector length: 4 KiB, as for face-domain embeddings.
pub const MAX_ENCODED_FACE_EMBEDDING_BYTES: usize = 4 * 1024;
/// `DeepIdentifier` embedding dimension.
pub const EMBEDDING_SIZE: usize = 512;
/// Normalized iris pixels: 128 x 1024, the Orb engine's `res_in_r` x `res_in_phi`.
pub const NORMALIZED_IRIS_LEN: usize = 128 * 1024;
/// Resized normalized iris pixels: 100 x 400.
pub const NORMALIZED_IRIS_RESIZED_LEN: usize = 100 * 400;
/// Value range of an int4-quantized embedding element.
pub const I4_RANGE: std::ops::RangeInclusive<i8> = -8..=7;

/// Checks each encoded image of `request` against [`MAX_IMAGE_BYTES`].
///
/// # Errors
/// Returns an `ImageTooLarge` failure located at the first oversized image.
pub fn check_image_limits(request: &MigrationRequest) -> Result<(), Failure> {
    for (image, role) in [
        (&request.face, ImageRole::Face),
        (&request.left_iris, ImageRole::LeftIris),
        (&request.right_iris, ImageRole::RightIris),
    ] {
        if image.len() > MAX_IMAGE_BYTES {
            return Err(
                Failure::invalid(invalid_request_reason::Reason::ImageTooLarge(
                    ByteLimitExceeded {
                        limit_bytes: MAX_IMAGE_BYTES as u64,
                    },
                ))
                .at_image(role),
            );
        }
    }
    Ok(())
}

impl Failure {
    /// Create a new `Failure` carrying the provided `code`.
    #[must_use]
    pub fn new(code: FailureCode) -> Self {
        Self {
            code: code as i32,
            ..Self::default()
        }
    }

    /// Shorthand instantiation of a `Failure` indicating an invalid request.
    #[must_use]
    pub fn invalid(reason: invalid_request_reason::Reason) -> Self {
        Self {
            invalid_request_reason: Some(InvalidRequestReason {
                reason: Some(reason),
            }),
            ..Self::new(FailureCode::InvalidRequest)
        }
    }

    /// Indicate for which image the failure occurred.
    #[must_use]
    pub fn at_image(mut self, role: ImageRole) -> Self {
        self.image = role as i32;
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
            .field("image", &crate::enum_debug::<ImageRole>(self.image))
            .field("invalid_request_reason", &self.invalid_request_reason)
            // `debug_report` can contain biometric diagnostics and must never enter logs.
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MigrationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationRequest").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MigrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationResult")
            .field("face_embedding", &self.face_embedding)
            .field("left_iris", &self.left_iris)
            .field("right_iris", &self.right_iris)
            .field("iris_code_version", &self.iris_code_version)
            .field("iris_model_version", &self.iris_model_version)
            .field("iris_embedding_version", &self.iris_embedding_version)
            .field("iris_inference_backend", &self.iris_inference_backend)
            // `debug_report` can contain biometric diagnostics and must never enter logs.
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FaceEmbedding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaceEmbedding")
            .field("r#type", &self.r#type)
            .field("version", &self.version)
            .field("inference_backend", &self.inference_backend)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NormalizedIris {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalizedIris").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EyeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EyeResult").finish_non_exhaustive()
    }
}
