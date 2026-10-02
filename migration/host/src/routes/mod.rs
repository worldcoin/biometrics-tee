//! HTTP route definitions. The API is cluster-internal; only Migration API pods call it.

mod attestation;
mod capacity;
mod health;
mod jobs;
mod readiness;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;

/// Builds the router.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/attestation", get(attestation::handler))
        .route("/jobs", post(jobs::submit))
        .route("/capacity", get(capacity::handler))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::{
        AppState, enclave, routes,
        test_support::{FailingEnclave, StubEnclave, state_with},
    };

    async fn probe(state: &AppState, path: &str) -> StatusCode {
        routes::handler()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should answer")
            .status()
    }

    fn unreachable_enclave() -> AppState {
        state_with(Arc::new(FailingEnclave(enclave::Error::Transport(
            "connection refused".to_owned(),
        ))))
    }

    #[tokio::test]
    async fn both_probes_pass_when_the_enclave_answers() {
        let state = state_with(Arc::new(StubEnclave::default()));

        assert_eq!(probe(&state, "/health").await, StatusCode::OK);
        assert_eq!(probe(&state, "/ready").await, StatusCode::OK);
    }

    /// Readiness follows the enclave, so a host whose enclave is down stops taking traffic.
    #[tokio::test]
    async fn readiness_fails_when_the_enclave_is_unreachable() {
        assert_eq!(
            probe(&unreachable_enclave(), "/ready").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Liveness does not, so a pod is not restarted for a dependency's outage.
    #[tokio::test]
    async fn liveness_holds_when_the_enclave_is_unreachable() {
        assert_eq!(
            probe(&unreachable_enclave(), "/health").await,
            StatusCode::OK
        );
    }
}
