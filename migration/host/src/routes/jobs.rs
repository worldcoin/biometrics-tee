use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState, enclave,
    error::ApiError,
    queue::{Admission, Full, Job},
};

/// A job dispatched by the API after it committed the row as `migrating`.
#[derive(Debug, Deserialize)]
pub struct JobRequest {
    job_id: String,
    object_key: String,
    sub: String,
    device_public_key: String,
    enclave_id: String,
}

/// The job is queued, either now or by an earlier dispatch.
#[derive(Debug, Serialize)]
pub struct JobAccepted {
    status: &'static str,
}

/// Validates and queues a job; the worker records its outcome in the job table.
pub async fn submit(
    State(state): State<AppState>,
    request: Result<Json<JobRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let Json(request) =
        request.map_err(|rejection| ApiError::invalid_job(rejection.body_text()))?;
    validate(&request)?;

    // Asked on every dispatch: a cached key could hide a restart and queue a job no key opens.
    let key = state
        .enclave_client()
        .encryption_key()
        .await
        .map_err(|error| ApiError::enclave(&error))?;
    if enclave::enclave_id(&key.public_key) != request.enclave_id {
        return Err(ApiError::enclave_changed());
    }

    let job = Job {
        job_id: request.job_id,
        object_key: request.object_key,
        sub: request.sub,
        device_public_key: request.device_public_key,
    };
    match state.queue().push(job) {
        Ok(Admission::Queued | Admission::Duplicate) => {
            Ok((StatusCode::ACCEPTED, Json(JobAccepted { status: "queued" })))
        }
        Err(Full) => Err(ApiError::host_busy()),
    }
}

/// The API builds every field; anything off here is a contract bug, so it fails loudly.
fn validate(request: &JobRequest) -> Result<(), ApiError> {
    if uuid::Uuid::parse_str(&request.job_id).is_err() {
        return Err(ApiError::invalid_job("job_id is not a UUID"));
    }
    // The host reads only the job's own object, whatever the caller sent.
    if request.object_key != di_migration_storage::layout::pcp_key(&request.job_id) {
        return Err(ApiError::invalid_job("object_key does not match job_id"));
    }
    if request.sub.trim().is_empty() || request.device_public_key.trim().is_empty() {
        return Err(ApiError::invalid_job(
            "sub and device_public_key are required",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::{
        AppState, enclave, routes,
        test_support::{FailingEnclave, StubEnclave, state_with, state_with_capacity},
    };

    const JOB_ID: &str = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a";

    fn body(enclave_id: &str) -> Value {
        json!({
            "job_id": JOB_ID,
            "object_key": format!("pcp/{JOB_ID}"),
            "sub": "sub",
            "device_public_key": "device-key",
            "enclave_id": enclave_id,
        })
    }

    fn current_enclave_id() -> String {
        enclave::enclave_id(&StubEnclave::default().public_key)
    }

    async fn submit(state: &AppState, body: &Value) -> (StatusCode, Value) {
        let response = routes::handler()
            .with_state(state.clone())
            .oneshot(
                Request::post("/jobs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
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
    async fn a_job_for_the_current_enclave_is_queued() {
        let state = state_with(Arc::new(StubEnclave::default()));

        let (status, response) = submit(&state, &body(&current_enclave_id())).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response["status"], "queued");
        assert_eq!(state.queue().queued(), 1);
    }

    /// The API may retry a dispatch; the job is not queued twice.
    #[tokio::test]
    async fn a_repeated_dispatch_is_accepted_once() {
        let state = state_with(Arc::new(StubEnclave::default()));

        submit(&state, &body(&current_enclave_id())).await;
        let (status, _) = submit(&state, &body(&current_enclave_id())).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(state.queue().queued(), 1);
    }

    #[tokio::test]
    async fn a_job_for_a_previous_boot_is_refused() {
        let state = state_with(Arc::new(StubEnclave::default()));

        let (status, response) = submit(&state, &body("an-old-boot")).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["error"]["code"], "enclave_changed");
        assert_eq!(response["allowRetry"], false);
        assert_eq!(state.queue().queued(), 0);
    }

    #[tokio::test]
    async fn a_full_host_is_busy() {
        let state = state_with_capacity(Arc::new(StubEnclave::default()), 1);
        submit(&state, &body(&current_enclave_id())).await;

        let mut second = body(&current_enclave_id());
        let other = "9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";
        second["job_id"] = json!(other);
        second["object_key"] = json!(format!("pcp/{other}"));
        let (status, response) = submit(&state, &second).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response["error"]["code"], "host_busy");
    }

    /// The host reads only the job's own object.
    #[tokio::test]
    async fn malformed_jobs_are_rejected() {
        let state = state_with(Arc::new(StubEnclave::default()));
        let id = current_enclave_id();
        let mut not_a_uuid = body(&id);
        not_a_uuid["job_id"] = json!("not-a-uuid");
        let mut foreign_object = body(&id);
        foreign_object["object_key"] = json!("pcp/someone-else");
        let mut no_sub = body(&id);
        no_sub["sub"] = json!(" ");
        let mut missing_field = body(&id);
        missing_field
            .as_object_mut()
            .expect("object")
            .remove("enclave_id");

        for request in [not_a_uuid, foreign_object, no_sub, missing_field] {
            let (status, response) = submit(&state, &request).await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{request}");
            assert_eq!(response["error"]["code"], "invalid_job");
        }
        assert_eq!(state.queue().queued(), 0);
    }

    #[tokio::test]
    async fn an_unreachable_enclave_queues_nothing() {
        let state = state_with(Arc::new(FailingEnclave(enclave::Error::Transport(
            "refused".to_owned(),
        ))));

        let (status, _) = submit(&state, &body(&current_enclave_id())).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.queue().queued(), 0);
    }
}
