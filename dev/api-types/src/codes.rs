//! Every `error.code` the host can return. Shared so the two ends cannot drift apart.

/// The request was not `application/octet-stream`.
pub const UNSUPPORTED_MEDIA_TYPE: &str = "unsupported_media_type";
/// The compressed body exceeded the limit.
pub const REQUEST_TOO_LARGE: &str = "request_too_large";
/// The body was unreadable or carried no PCP.
pub const INVALID_REQUEST: &str = "invalid_request";
/// A migration is already running.
pub const MIGRATION_IN_PROGRESS: &str = "migration_in_progress";
/// The PCP was not gzip.
pub const UNSUPPORTED_COMPRESSION: &str = "unsupported_compression";
/// The PCP expanded past the limit.
pub const PCP_TOO_LARGE: &str = "pcp_too_large";
/// The gzip stream did not decode.
pub const INVALID_PCP: &str = "invalid_pcp";
/// The enclave did not finish in time.
pub const ENCLAVE_TIMEOUT: &str = "enclave_timeout";
/// The enclave was unreachable.
pub const ENCLAVE_UNREACHABLE: &str = "enclave_unreachable";
/// The host failed; detail stays in its log.
pub const INTERNAL_ERROR: &str = "internal_error";
