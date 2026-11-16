use reqwest::{StatusCode, Url};

use crate::sealing::SealingError;

/// A migration client failure. Inspect [`Self::reason`] and [`Self::allow_retry`]
/// without parsing its display text; underlying failures remain in the source chain.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("migration client failed ({reason}): {source}")]
    ClientOperationFailed {
        reason: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{base_url} is not a valid migration API base URL")]
    InvalidBaseUrl { base_url: Url },
    #[error("migration request failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("migration API answered {status}: {code}: {message} (allow retry: {allow_retry})")]
    HttpResponse {
        status: StatusCode,
        code: String,
        message: String,
        allow_retry: bool,
    },
    #[error("the sealed debug report exceeds the {limit} byte limit")]
    DebugReportTooLarge { limit: usize },
    #[error(transparent)]
    Sealing(#[from] SealingError),
}

impl ClientError {
    /// Fallback for HTTP failures without a structured API error envelope.
    pub(crate) fn http(status: StatusCode) -> Self {
        Self::HttpResponse {
            status,
            code: "unexpected_status".into(),
            message: status
                .canonical_reason()
                .unwrap_or("HTTP request failed")
                .into(),
            allow_retry: matches!(
                status,
                StatusCode::REQUEST_TIMEOUT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::INTERNAL_SERVER_ERROR
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            ),
        }
    }

    /// The API's error code, or a client-side failure reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::ClientOperationFailed { reason, .. } => reason,
            Self::InvalidBaseUrl { .. } => "invalid_base_url",
            Self::Transport(error) if error.is_timeout() => "request_timeout",
            Self::Transport(_) => "request_failed",
            Self::HttpResponse { code, .. } => code,
            Self::DebugReportTooLarge { .. } => "debug_report_too_large",
            Self::Sealing(error) => match error {
                SealingError::InvalidBase64 { .. } => "invalid_base64",
                SealingError::Attestation(_) => "attestation_failed",
                SealingError::EnclaveIdMismatch { .. } => "enclave_id_mismatch",
                SealingError::Encode => "payload_encoding_failed",
                SealingError::Seal(_) => "sealing_failed",
                SealingError::Open(_) => "unsealing_failed",
                SealingError::InvalidDevicePublicKey => "invalid_device_public_key",
                SealingError::ResponseOpenerError(_) => "invalid_response_secret",
            },
        }
    }

    /// Whether retrying the failed step may succeed. No retries are performed here.
    ///
    /// API responses use the server's explicit flag. Without an API envelope, only
    /// transient HTTP statuses and connection, timeout or body-transfer failures qualify.
    /// Local and cryptographic failures require investigation or corrected input.
    /// For `start_migration`, reconcile the job status before restarting the whole flow:
    /// the error does not imply that earlier steps were rolled back.
    #[must_use]
    pub fn allow_retry(&self) -> bool {
        match self {
            Self::HttpResponse { allow_retry, .. } => *allow_retry,
            Self::Transport(error) => error.is_connect() || error.is_timeout() || error.is_body(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn retry_guidance_uses_the_api_flag_before_the_http_status() {
        for (status, allow_retry) in [
            (StatusCode::CONFLICT, true),
            (StatusCode::SERVICE_UNAVAILABLE, false),
        ] {
            let error = ClientError::HttpResponse {
                status,
                code: "test_reason".into(),
                message: "Test failure".into(),
                allow_retry,
            };
            assert_eq!(error.reason(), "test_reason");
            assert_eq!(error.allow_retry(), allow_retry);
            assert!(error.to_string().contains("Test failure"));
        }
    }

    #[test]
    fn only_transient_http_failures_allow_retry_without_an_api_envelope() {
        for (status, expected) in [
            (StatusCode::REQUEST_TIMEOUT, true),
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::INTERNAL_SERVER_ERROR, true),
            (StatusCode::BAD_GATEWAY, true),
            (StatusCode::SERVICE_UNAVAILABLE, true),
            (StatusCode::GATEWAY_TIMEOUT, true),
            (StatusCode::BAD_REQUEST, false),
            (StatusCode::FORBIDDEN, false),
            (StatusCode::NOT_FOUND, false),
            (StatusCode::CONFLICT, false),
            (StatusCode::NOT_IMPLEMENTED, false),
        ] {
            let error = ClientError::http(status);
            assert_eq!(error.allow_retry(), expected);
            assert_eq!(error.reason(), "unexpected_status");
            assert!(
                matches!(error, ClientError::HttpResponse { status: actual, ref message, .. }
                if actual == status && message == status.canonical_reason().unwrap())
            );
        }
    }

    #[test]
    fn local_failures_keep_the_cause_and_do_not_allow_retry() {
        let error = ClientError::ClientOperationFailed {
            reason: "invalid_response",
            source: Box::new(std::io::Error::other("bad data")),
        };
        assert_eq!(error.reason(), "invalid_response");
        assert!(!error.allow_retry());
        assert_eq!(error.source().unwrap().to_string(), "bad data");
        assert!(!ClientError::Sealing(SealingError::InvalidDevicePublicKey).allow_retry());
    }
}
