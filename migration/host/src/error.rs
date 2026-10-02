//! Every route returns [`ApiError`], so status, body and logging are decided in one place.
//! Constructors are per route rather than a blanket `From`: the mapping is context-dependent.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use di_migration_primitives::host_api::{ErrorBody, ErrorEnvelope, codes};

use crate::enclave;

/// An API failure, with the status and body to return for it.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow_retry: bool,
    /// The dependency that failed, logged on 5xx.
    dependency: Option<&'static str>,
    /// Log-only context; never serialized, since it may name internals.
    detail: Option<String>,
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
            dependency: None,
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The status this error will return.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The machine-readable code this error will return.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Whether the caller is told to retry.
    #[must_use]
    pub const fn allow_retry(&self) -> bool {
        self.allow_retry
    }

    /// A job request that failed validation; resending it unchanged cannot succeed.
    #[must_use]
    pub fn invalid_job(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            codes::INVALID_JOB,
            "The job request is invalid",
            false,
        )
        .with_detail(detail)
    }

    /// A job sealed to another boot's key; the PCP can never be opened here, so the app restarts.
    #[must_use]
    pub const fn enclave_changed() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            codes::ENCLAVE_CHANGED,
            "The enclave restarted since the job was assigned",
            false,
        )
    }

    /// The safety cap was hit. Not retried: the job is pinned here and the API fails it.
    #[must_use]
    pub const fn host_busy() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            codes::HOST_BUSY,
            "The host is at capacity",
            false,
        )
    }

    /// Maps an enclave failure on a control call such as the attestation read.
    #[must_use]
    pub fn enclave(error: &enclave::Error) -> Self {
        let mapped = match error {
            enclave::Error::Timeout => Self::new(
                StatusCode::GATEWAY_TIMEOUT,
                codes::ENCLAVE_TIMEOUT,
                "The enclave did not answer in time",
                true,
            ),
            enclave::Error::Transport(detail) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                codes::ENCLAVE_UNREACHABLE,
                "The enclave was unreachable",
                true,
            )
            .with_detail(detail.clone()),
            enclave::Error::Operation(operation) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL_ERROR,
                "Internal server error",
                true,
            )
            .with_detail(format!("{operation:?}")),
        };
        Self {
            dependency: Some("enclave"),
            ..mapped
        }
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
                code: self.code.to_owned(),
                message: self.message.to_owned(),
            },
        };
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use di_migration_enclave_types as enclave_types;

    use di_migration_primitives::host_api::codes;

    use super::ApiError;
    use crate::enclave;

    /// Pins the enclave matrix; nothing else fails if one arm is changed alone.
    #[test]
    fn each_enclave_failure_maps_to_its_own_status() {
        let cases = [
            (
                enclave::Error::Timeout,
                StatusCode::GATEWAY_TIMEOUT,
                codes::ENCLAVE_TIMEOUT,
            ),
            (
                enclave::Error::Transport("boom".to_owned()),
                StatusCode::SERVICE_UNAVAILABLE,
                codes::ENCLAVE_UNREACHABLE,
            ),
            (
                enclave::Error::Operation(enclave_types::Error::Internal),
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL_ERROR,
            ),
        ];

        for (error, status, code) in cases {
            let mapped = ApiError::enclave(&error);

            assert_eq!(mapped.status(), status, "status for {error:?}");
            assert_eq!(mapped.code(), code, "code for {error:?}");
            assert!(mapped.allow_retry(), "{code} should be retryable");
        }
    }
}
