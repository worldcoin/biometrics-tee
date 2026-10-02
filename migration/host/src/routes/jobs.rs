use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
};
use di_migration_primitives::host_api::{JobAccepted, JobRequest};
use di_migration_storage::schema::pcp_key;

use crate::{
    AppState, enclave,
    error::ApiError,
    queue::{Admission, Full},
};

/// Validates and queues a job the API committed as `migrating`; the worker records its outcome.
pub async fn handler(
    State(state): State<AppState>,
    request: Result<Json<JobRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    // A malformed `job_id` or `enclave_id` already fails here, while deserializing.
    let Json(job) = request.map_err(|rejection| ApiError::invalid_job(rejection.body_text()))?;
    validate(&job)?;

    // Asked on every dispatch: a cached key could hide a restart and queue a job no key opens.
    let key = state
        .enclave_client()
        .encryption_key()
        .await
        .map_err(|error| ApiError::enclave(&error))?;
    if enclave::enclave_id(&key.public_key) != job.enclave_id {
        return Err(ApiError::enclave_changed());
    }

    match state.queue().push(job) {
        Ok(Admission::Queued | Admission::Duplicate) => {
            Ok((StatusCode::ACCEPTED, Json(JobAccepted::queued())))
        }
        Err(Full) => Err(ApiError::host_busy()),
    }
}

/// The API builds every field; anything off here is a contract bug, so it fails loudly.
fn validate(job: &JobRequest) -> Result<(), ApiError> {
    // The host reads only the job's own object, whatever the caller sent.
    if job.object_key != pcp_key(&job.job_id) {
        return Err(ApiError::invalid_job("object_key does not match job_id"));
    }
    if job.sub.trim().is_empty() || job.device_public_key.trim().is_empty() {
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
        test_support::{FailingEnclave, StubEnclave, job, state_with, state_with_capacity},
    };

    fn body(n: u64) -> Value {
        serde_json::to_value(job(n)).expect("job should serialize")
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

        let (status, response) = submit(&state, &body(1)).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response["status"], "queued");
        assert_eq!(state.queue().queued(), 1);
    }

    /// The API may retry a dispatch; the job is not queued twice.
    #[tokio::test]
    async fn a_repeated_dispatch_is_accepted_once() {
        let state = state_with(Arc::new(StubEnclave::default()));

        submit(&state, &body(1)).await;
        let (status, _) = submit(&state, &body(1)).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(state.queue().queued(), 1);
    }

    #[tokio::test]
    async fn a_job_for_a_previous_boot_is_refused() {
        let state = state_with(Arc::new(StubEnclave::default()));
        let mut previous_boot = body(1);
        previous_boot["enclave_id"] = json!(enclave::enclave_id(b"a previous boot's key").as_str());

        let (status, response) = submit(&state, &previous_boot).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["error"]["code"], "enclave_changed");
        assert_eq!(response["allowRetry"], false);
        assert_eq!(state.queue().queued(), 0);
    }

    #[tokio::test]
    async fn a_full_host_is_busy() {
        let state = state_with_capacity(Arc::new(StubEnclave::default()), 1);
        submit(&state, &body(1)).await;

        let (status, response) = submit(&state, &body(2)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response["error"]["code"], "host_busy");
    }

    /// The host reads only the job's own object.
    #[tokio::test]
    async fn malformed_jobs_are_rejected() {
        let state = state_with(Arc::new(StubEnclave::default()));
        let mut not_a_uuid = body(1);
        not_a_uuid["job_id"] = json!("not-a-uuid");
        let mut foreign_object = body(1);
        foreign_object["object_key"] = json!("pcp/someone-else");
        let mut no_sub = body(1);
        no_sub["sub"] = json!(" ");
        let mut bad_enclave_id = body(1);
        bad_enclave_id["enclave_id"] = json!("not-hex");
        let mut missing_field = body(1);
        missing_field
            .as_object_mut()
            .expect("object")
            .remove("enclave_id");

        for request in [
            not_a_uuid,
            foreign_object,
            no_sub,
            bad_enclave_id,
            missing_field,
        ] {
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

        let (status, _) = submit(&state, &body(1)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.queue().queued(), 0);
    }
}
