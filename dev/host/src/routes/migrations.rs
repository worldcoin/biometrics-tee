use axum::{
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use di_dev_api_types::{MAX_PCP_BYTES, MIGRATION_CONTENT_TYPE, codes};
use di_dev_enclave_types::MigrateRequest;

use crate::{AppState, compression, error::ApiError};

/// Migrates one PCP and returns it. Runs to completion before answering; the enclave deadline
/// in `enclave.rs` is what bounds how long a client waits.
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(MIGRATION_CONTENT_TYPE)
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            codes::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/octet-stream",
            false,
        ));
    }

    let body = body.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                codes::REQUEST_TOO_LARGE,
                "The compressed PCP exceeded the body limit",
                false,
            )
        } else {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                codes::INVALID_REQUEST,
                "Could not read the request body",
                false,
            )
            .with_detail(error.to_string())
        }
    })?;

    if body.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            codes::INVALID_REQUEST,
            "The request carried no PCP",
            false,
        ));
    }

    let pcp = compression::decompress(&body, MAX_PCP_BYTES).map_err(|e| ApiError::payload(&e))?;

    // Acquired after decompression so a malformed payload never holds the slot. The permit
    // drops with the handler, however it returns.
    let migration = state.migration();
    let Ok(_permit) = migration.try_acquire() else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            codes::MIGRATION_IN_PROGRESS,
            "A migration is already running; retry once it finishes",
            true,
        ));
    };

    let bytes = pcp.len();
    tracing::info!(bytes, "migration started");

    let migrated = state
        .enclave_client()
        .migrate(MigrateRequest { pcp: pcp.into() })
        .await
        .map_err(|error| {
            tracing::error!(?error, dependency = "enclave", "migration failed");
            ApiError::enclave(&error)
        })?
        .pcp;

    tracing::info!(bytes = migrated.len(), "migration finished");

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, MIGRATION_CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        migrated,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use di_dev_api_types::{ErrorEnvelope, MAX_PCP_BYTES, MIGRATION_CONTENT_TYPE};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{
        AppState, enclave, routes,
        test_support::{EchoEnclave, FailingEnclave, GatedEnclave, state_with},
    };

    const PCP: &[u8] = b"a perfectly ordinary pcp";

    fn gzip(payload: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).expect("should encode");
        encoder.finish().expect("should finish")
    }

    async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, bytes::Bytes) {
        let response = routes::handler(MAX_PCP_BYTES)
            .with_state(state.clone())
            .oneshot(request)
            .await
            .expect("router should answer");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body should read")
            .to_bytes();
        (status, body)
    }

    fn submission(body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/migrations")
            .header(header::CONTENT_TYPE, MIGRATION_CONTENT_TYPE)
            .body(Body::from(body))
            .expect("request should build")
    }

    fn code_of(body: &bytes::Bytes) -> String {
        serde_json::from_slice::<ErrorEnvelope>(body)
            .expect("error envelope")
            .error
            .code
    }

    #[tokio::test]
    async fn a_pcp_comes_back_migrated_and_decompressed() {
        let state = state_with(Arc::new(EchoEnclave));

        let (status, body) = send(&state, submission(gzip(PCP))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), PCP);
    }

    /// The second request arrives while the first is inside the enclave, which is the only
    /// window in which the slot is held.
    #[tokio::test]
    async fn a_second_migration_is_refused_while_one_runs() {
        let (fake, entered, release) = GatedEnclave::new();
        let state = state_with(Arc::new(fake));

        let first = tokio::spawn({
            let state = state.clone();
            async move { send(&state, submission(gzip(PCP))).await }
        });
        entered.notified().await;

        let (status, body) = send(&state, submission(gzip(PCP))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(code_of(&body), "migration_in_progress");

        release.notify_one();
        let (status, body) = first.await.expect("first request should finish");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), PCP);
    }

    /// A bad payload must not occupy the slot — it is rejected before the permit is taken.
    #[tokio::test]
    async fn an_uncompressed_payload_is_rejected_without_taking_the_slot() {
        let state = state_with(Arc::new(EchoEnclave));

        let (status, _) = send(&state, submission(PCP.to_vec())).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let (status, _) = send(&state, submission(gzip(PCP))).await;
        assert_eq!(status, StatusCode::OK, "the slot should still be free");
    }

    #[tokio::test]
    async fn a_request_without_the_binary_content_type_is_rejected() {
        let state = state_with(Arc::new(EchoEnclave));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/migrations")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(gzip(PCP)))
            .expect("request should build");

        let (status, _) = send(&state, request).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn an_empty_body_is_rejected() {
        let state = state_with(Arc::new(EchoEnclave));

        let (status, _) = send(&state, submission(Vec::new())).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unreachable_enclave_is_a_bad_gateway() {
        let state = state_with(Arc::new(FailingEnclave(enclave::Error::Transport(
            "connection refused".to_owned(),
        ))));

        let (status, body) = send(&state, submission(gzip(PCP))).await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(code_of(&body), "enclave_unreachable");
    }

    /// The slot must be free again after a failure, or one dead enclave call wedges the host.
    #[tokio::test]
    async fn an_enclave_timeout_is_a_gateway_timeout_and_frees_the_slot() {
        let state = state_with(Arc::new(FailingEnclave(enclave::Error::Timeout)));

        let (status, body) = send(&state, submission(gzip(PCP))).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(code_of(&body), "enclave_timeout");

        let (status, _) = send(&state, submission(gzip(PCP))).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "not a 409");
    }

    /// The body limit and the decompression ceiling are the same number, and both answer 413,
    /// so the code is what proves decompression rejected this rather than the body limit.
    #[tokio::test]
    async fn a_compression_bomb_is_rejected_by_the_decompression_ceiling() {
        let state = state_with(Arc::new(EchoEnclave));
        let bomb = gzip(&vec![0u8; MAX_PCP_BYTES + 1]);
        assert!(
            bomb.len() < MAX_PCP_BYTES,
            "the bomb must clear the body limit"
        );

        let (status, body) = send(&state, submission(bomb)).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(code_of(&body), "pcp_too_large");
    }
}
