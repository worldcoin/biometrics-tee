//! HTTP route definitions.

mod health;
mod migrations;
mod readiness;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::AppState;

/// Builds the router; the body limit hangs off the migrations route alone.
pub fn handler(max_request_bytes: usize) -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route(
            "/v1/migrations",
            post(migrations::handler).layer(DefaultBodyLimit::max(max_request_bytes)),
        )
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
        AppState,
        enclave::{self, EnclaveClient},
        routes,
        test_support::{EchoEnclave, FailingEnclave, state_with},
    };

    async fn probe(state: &AppState, path: &str) -> StatusCode {
        routes::handler(1024 * 1024)
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
        let state = state_with(Arc::new(EchoEnclave));

        assert_eq!(probe(&state, "/health").await, StatusCode::OK);
        assert_eq!(probe(&state, "/ready").await, StatusCode::OK);
    }

    /// Readiness follows the enclave, so a host whose enclave is down stops taking traffic.
    #[tokio::test]
    async fn readiness_fails_when_the_enclave_is_unreachable() {
        let state = unreachable_enclave();

        assert_eq!(
            probe(&state, "/ready").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Liveness does not, so a pod is not restarted for a dependency's outage.
    #[tokio::test]
    async fn liveness_holds_when_the_enclave_is_unreachable() {
        let state = unreachable_enclave();

        assert_eq!(probe(&state, "/health").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_enclave_client_trait_object_is_shareable() {
        let _: Arc<dyn EnclaveClient> = Arc::new(EchoEnclave);
    }
}
