use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use di_migration_primitives::host_api::AttestationResponse;

use crate::{AppState, enclave, error::ApiError};

/// Relays this boot's key attestation; the app verifies it, not the host.
pub async fn handler(State(state): State<AppState>) -> Result<Json<AttestationResponse>, ApiError> {
    let key = state
        .enclave_client()
        .encryption_key()
        .await
        .map_err(|error| ApiError::enclave(&error))?;

    Ok(Json(AttestationResponse {
        enclave_id: enclave::enclave_id(&key.public_key),
        attestation: STANDARD.encode(&key.document),
        enclave_public_key: STANDARD.encode(&key.public_key),
        host_ip: state.host_ip(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{
        AppState, enclave, routes,
        test_support::{FailingEnclave, StubEnclave, state_with},
    };

    async fn attest(state: AppState) -> (StatusCode, serde_json::Value) {
        let response = routes::handler()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/attestation")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should answer");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body should read")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).expect("body should be JSON"),
        )
    }

    #[tokio::test]
    async fn the_attestation_carries_the_key_its_id_and_this_hosts_ip() {
        let enclave = StubEnclave::default();
        let public_key = enclave.public_key.clone();

        let (status, body) = attest(state_with(Arc::new(enclave))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["enclave_id"],
            enclave::enclave_id(&public_key).as_str()
        );
        assert_eq!(body["enclave_public_key"], STANDARD.encode(&public_key));
        assert_eq!(body["attestation"], STANDARD.encode(b"document"));
        assert_eq!(body["host_ip"], "10.0.0.7");
    }

    #[tokio::test]
    async fn an_unreachable_enclave_is_retryable_and_unavailable() {
        let state = state_with(Arc::new(FailingEnclave(enclave::Error::Transport(
            "connection refused".to_owned(),
        ))));

        let (status, body) = attest(state).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "enclave_unreachable");
        assert_eq!(body["allowRetry"], true);
    }
}
