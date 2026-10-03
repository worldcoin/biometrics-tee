//! Every route returns [`ApiError`], so status, body and logging are decided in one place.

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use di_migration_primitives::app_api::codes;
use serde::Serialize;

/// An API failure, with the status and body to return for it.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow_retry: bool,
    /// Seconds for the `Retry-After` header.
    retry_after: Option<u64>,
    /// The dependency that failed, logged on 5xx.
    dependency: Option<&'static str>,
    /// Log-only context; never serialized, since it may name internals.
    detail: Option<String>,
}

/// The JSON body of every error response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    allow_retry: bool,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        allow_retry: bool,
    ) -> Self {
        Self {
            status,
            code,
            message,
            allow_retry,
            retry_after: None,
            dependency: None,
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    const fn with_dependency(mut self, dependency: &'static str) -> Self {
        self.dependency = Some(dependency);
        self
    }

    /// The status this error will return.
    #[cfg(test)]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The machine-readable code this error will return.
    #[cfg(test)]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The device key is missing or invalid.
    pub const fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            codes::UNAUTHENTICATED,
            "The device could not be authenticated",
            false,
        )
    }

    /// No host has room; an expected limit, so not a 5xx.
    pub const fn at_capacity(retry_after_secs: u64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            codes::AT_CAPACITY,
            "The migration service is at capacity",
            true,
        );
        error.retry_after = Some(retry_after_secs);
        error
    }

    /// The `sub` already has an active migration.
    pub const fn migration_in_progress() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            codes::MIGRATION_IN_PROGRESS,
            "A migration is already in progress",
            false,
        )
    }

    /// The chosen host did not answer.
    pub fn host(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "A dependency is unavailable",
            true,
        )
        .with_dependency("host")
        .with_detail(detail)
    }

    /// The body is not a valid request.
    pub const fn invalid_request() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request body is invalid",
            false,
        )
    }

    /// A `sub` that is blank, too long or has control characters.
    pub const fn invalid_sub() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_sub",
            "The subject is invalid",
            false,
        )
    }

    /// Maps an ownership-proof failure: bad input is 400, a rejected proof 403, and an outage of
    /// the verification service 503.
    pub fn proof(error: &proof::ProofVerificationError) -> Self {
        match error {
            proof::ProofVerificationError::VerificationRejected => Self::new(
                StatusCode::FORBIDDEN,
                error.as_str(),
                "The ownership proof was rejected",
                false,
            ),
            proof::ProofVerificationError::VerificationError => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                error.as_str(),
                "The ownership proof could not be verified",
                true,
            )
            .with_dependency("proof-verification"),
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                error.as_str(),
                "The ownership proof request is invalid",
                false,
            ),
        }
    }

    /// The fleet's load is unknown, e.g. every recent capacity poll failed.
    pub const fn capacity_unknown() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_unknown",
            "The fleet's capacity is unknown",
            true,
        )
        .with_dependency("host")
    }

    /// The job table or bucket failed.
    pub fn storage(dependency: &'static str, detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "A dependency is unavailable",
            true,
        )
        .with_dependency(dependency)
        .with_detail(detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let detail = self.detail.as_deref().unwrap_or_default();
        if self.status.is_server_error() {
            tracing::error!(
                code = self.code,
                status = %self.status,
                detail,
                dependency = self.dependency.unwrap_or_default(),
                "request failed"
            );
        } else {
            tracing::warn!(code = self.code, status = %self.status, detail, "request rejected");
        }

        let body = ErrorEnvelope {
            allow_retry: self.allow_retry,
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };
        let mut response = (self.status, Json(body)).into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::ApiError;

    /// Pins the proof matrix; the app retries only what can succeed on retry.
    #[test]
    fn proof_failures_map_to_their_own_status() {
        let cases = [
            (
                proof::ProofVerificationError::VerificationRejected,
                StatusCode::FORBIDDEN,
            ),
            (
                proof::ProofVerificationError::VerificationError,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                proof::ProofVerificationError::ProofMissing,
                StatusCode::BAD_REQUEST,
            ),
            (
                proof::ProofVerificationError::Oversized,
                StatusCode::BAD_REQUEST,
            ),
        ];

        for (error, status) in cases {
            let mapped = ApiError::proof(&error);

            assert_eq!(mapped.status(), status, "{error:?}");
            assert_eq!(mapped.code(), error.as_str());
        }
    }
}
