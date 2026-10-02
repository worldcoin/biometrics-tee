use axum::http::StatusCode;

/// Liveness only: restarting the host would not fix a dead enclave, so this ignores it.
pub async fn handler() -> StatusCode {
    StatusCode::OK
}
