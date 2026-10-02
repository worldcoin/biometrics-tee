use axum::{extract::State, http::StatusCode};

use crate::AppState;

/// Readiness: the host takes traffic only while its enclave answers.
pub async fn handler(State(state): State<AppState>) -> StatusCode {
    if state.readiness().is_ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
