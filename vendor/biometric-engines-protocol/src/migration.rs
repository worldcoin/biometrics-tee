//! Public generated migration messages and small construction helpers.
pub use crate::generated::migration::v1::*;

/// Per encoded image: 16 MiB.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
/// Base64 length of a packed v2.1 iris or mask code: 16 x 200 x 2 x 2 bits, 1,600 bytes.
pub const ENCODED_CODE_LEN: usize = 2136;
/// `DeepIdentifier` embedding dimension.
pub const EMBEDDING_SIZE: usize = 512;
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
            .finish()
    }
}

impl std::fmt::Debug for MigrationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationRequest").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EyeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EyeResult").finish_non_exhaustive()
    }
}
