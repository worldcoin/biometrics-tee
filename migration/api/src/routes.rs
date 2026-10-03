use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use di_migration_primitives::{
    JobId,
    app_api::{InitMigrationRequest, InitMigrationResponse},
};
use di_migration_storage::{NewJob, StorageError};

use crate::{
    AppState,
    error::ApiError,
    fleet::{FleetLoad, Placement},
};

/// Bounds the subject we accept; real subjects are short opaque identifiers.
const MAX_SUB_LEN: usize = 255;

/// Base `Retry-After` when the fleet is full; up to as much again is added as jitter, so
/// rejected apps do not return together.
const AT_CAPACITY_RETRY_AFTER_SECS: u64 = 30;

/// How long job rows outlive their job; `DynamoDB` deletes them afterwards.
const JOB_RETENTION: Duration = Duration::from_secs(2 * 24 * 60 * 60);

/// The public API the app calls, exposed through the gateway.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/init-migration", post(init_migration))
        .with_state(state)
}

/// Cluster-internal routes on their own listener, which is never routed publicly; the public
/// router has no path to them, whatever the gateway forwards.
pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/internal/capacity", get(capacity))
        .with_state(state)
}

/// The fleet's summed load for the notification scheduler, which pauses prompting on an error.
async fn capacity(State(state): State<AppState>) -> Result<Json<FleetLoad>, ApiError> {
    state
        .fleet
        .totals()
        .map(Json)
        .ok_or_else(ApiError::capacity_unknown)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    let (jobs_result, bucket_result) =
        tokio::join!(state.jobs.check_ready(), state.bucket.check_ready());

    if let Err(error) = &jobs_result {
        tracing::warn!(%error, dependency = "dynamodb", "readiness check failed");
    }
    if let Err(error) = &bucket_result {
        tracing::warn!(%error, dependency = "s3", "readiness check failed");
    }
    if jobs_result.is_ok() && bucket_result.is_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Verifies ownership, admits and places the job, and returns where to seal and upload the PCP.
async fn init_migration(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<InitMigrationResponse>, ApiError> {
    let device_public_key = state
        .authenticator
        .authenticate(&headers, &body)
        .map_err(|_| ApiError::unauthenticated())?;
    let request: InitMigrationRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid_request())?;
    let sub = request.sub.trim();
    if sub.is_empty() || sub.len() > MAX_SUB_LEN || sub.chars().any(char::is_control) {
        return Err(ApiError::invalid_sub());
    }

    let verification = proof::VerificationRequest {
        challenge_id: request.challenge_id,
        challenge_type: state.verifier.config.challenge_type.clone(),
        credential_sub: sub.to_owned(),
        proof: request.proof,
    };
    state
        .verifier
        .verify(verification)
        .await
        .map_err(|error| ApiError::proof(&error))?;

    // Admission before the lock: a full fleet leaves nothing to release.
    let host = match state.fleet.place() {
        Placement::Host(host) => host,
        Placement::AtCapacity => {
            return Err(ApiError::at_capacity(
                AT_CAPACITY_RETRY_AFTER_SECS + fastrand::u64(..=AT_CAPACITY_RETRY_AFTER_SECS),
            ));
        }
        Placement::Unknown => return Err(ApiError::capacity_unknown()),
    };
    let attestation = state
        .hosts
        .attestation(host)
        .await
        .map_err(|error| ApiError::host(error.to_string()))?;

    let now = unix_now();
    let job = NewJob {
        job_id: JobId::new(),
        sub: sub.to_owned(),
        device_public_key,
        // The address we reached, which migrate dials again.
        host_ip: host.ip(),
        enclave_id: attestation.enclave_id.clone(),
        created_at: now,
        active_until: now + state.upload_window.as_secs(),
        expires_at: now + JOB_RETENTION.as_secs(),
    };
    state
        .jobs
        .create_job(&job)
        .await
        .map_err(|error| match error {
            StorageError::ActiveJob => ApiError::migration_in_progress(),
            error => ApiError::storage("dynamodb", error.to_string()),
        })?;

    let upload_url = state
        .bucket
        .presign_upload(&job.job_id, state.presigned_url_ttl)
        .await
        .map_err(|error| ApiError::storage("s3", error.to_string()))?;

    Ok(Json(InitMigrationResponse {
        enclave_id: attestation.enclave_id,
        attestation: attestation.attestation,
        enclave_public_key: attestation.enclave_public_key,
        upload_url,
        migrate_by: job.active_until,
    }))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
