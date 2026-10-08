use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use di_migration_primitives::{
    JobId, Reason, Status,
    app_api::{
        DEVICE_KEY_THUMBPRINT, InitMigrationRequest, InitMigrationResponse, MigrateRequest,
        MigrateResponse, MigrationStatus,
    },
    host_api::JobRequest,
};
use di_migration_storage::{JobRecord, NewJob, StorageError, schema::pcp_key};

use crate::{
    AppState, device_key,
    error::ApiError,
    fleet::{FleetLoad, Placement},
    host_client::DispatchError,
};

/// Bounds the subject we accept; real subjects are short opaque identifiers.
const MAX_SUB_LEN: usize = 255;

/// Bounds the device key we store; a real key is a few hundred bytes of base64.
const MAX_DEVICE_KEY_LEN: usize = 1024;

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
        .route("/v1/migrations/{sub}", post(migrate).get(migration_status))
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
    Json(request): Json<InitMigrationRequest>,
) -> Result<Json<InitMigrationResponse>, ApiError> {
    let device_public_key = device_public_key(&headers).ok_or_else(ApiError::invalid_device_key)?;
    let sub = valid_sub(&request.sub)?;

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
    // Presign before taking the lock, so a failure here leaves nothing that blocks a retry.
    let upload_url = state
        .bucket
        .presign_upload(&job.job_id, state.presigned_url_ttl)
        .await
        .map_err(|error| ApiError::storage("s3", error.to_string()))?;
    match state.jobs.create_job(&job).await {
        Ok(()) => {}
        Err(StorageError::ActiveJob) => replace_unclaimed_job(&state, &job).await?,
        Err(error) => return Err(ApiError::storage("dynamodb", error.to_string())),
    }

    Ok(Json(InitMigrationResponse {
        enclave_id: attestation.enclave_id,
        attestation: attestation.attestation,
        enclave_public_key: attestation.enclave_public_key,
        upload_url,
        migrate_by: job.active_until,
    }))
}

/// Starts over for an app that holds an unclaimed job, e.g. it lost the init response or never
/// uploaded; nothing was queued for that job yet. Any other active job stays in progress.
async fn replace_unclaimed_job(state: &AppState, job: &NewJob) -> Result<(), ApiError> {
    let current = state
        .jobs
        .latest_job(&job.sub)
        .await
        .map_err(|error| ApiError::storage("dynamodb", error.to_string()))?;
    let Some(current) = current.filter(|current| {
        current.status == Status::Created && current.device_public_key == job.device_public_key
    }) else {
        return Err(ApiError::migration_in_progress());
    };
    state
        .jobs
        .replace_job(job, &current.job_id)
        .await
        .map_err(|error| match error {
            // Claimed or replaced concurrently.
            StorageError::ActiveJob => ApiError::migration_in_progress(),
            error => ApiError::storage("dynamodb", error.to_string()),
        })
}

/// Hands the uploaded PCP's job to its host. The claim commits `migrating` first, so a retried
/// migrate never runs the job twice; a dispatch failure fails the job and frees the `sub`.
async fn migrate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub): Path<String>,
    Json(request): Json<MigrateRequest>,
) -> Result<(StatusCode, Json<MigrateResponse>), ApiError> {
    let (sub, job) = owned_job(&state, &headers, &sub).await?;
    // The enclave seals this key, so it must be the one the proxy attested for this job.
    let device_key = device_key::canonicalize(&request.device_public_key)
        .ok_or_else(ApiError::invalid_device_key)?;
    if device_key.thumbprint != job.device_public_key {
        return Err(ApiError::device_key_mismatch());
    }
    let now = unix_now();
    if job.status != Status::Created {
        // A retry after an earlier call committed: report where that call left the job.
        return already_claimed(&job, now);
    }
    if now > job.created_at + state.upload_window.as_secs() {
        return Err(ApiError::expired());
    }
    let uploaded = state
        .bucket
        .pcp_exists(&job.job_id)
        .await
        .map_err(|error| ApiError::storage("s3", error.to_string()))?;
    if !uploaded {
        return Err(ApiError::not_uploaded());
    }

    let deadline = now + state.job_deadline.as_secs();
    match state.jobs.claim(&job.job_id, sub, now, deadline).await {
        Ok(()) => {}
        Err(StorageError::UploadWindowPassed) => return Err(ApiError::expired()),
        Err(StorageError::NotCreated) => {
            // A concurrent migrate claimed it first.
            let (_, job) = owned_job(&state, &headers, sub).await?;
            return already_claimed(&job, now);
        }
        Err(error) => return Err(ApiError::storage("dynamodb", error.to_string())),
    }

    let host = SocketAddr::new(job.host_ip, state.host_port);
    let request = JobRequest {
        object_key: pcp_key(&job.job_id),
        job_id: job.job_id.clone(),
        sub: sub.to_owned(),
        device_public_key: device_key.jwk,
        enclave_id: job.enclave_id,
        deadline,
    };
    let Err(error) = state.hosts.submit(host, &request).await else {
        return Ok(accepted(deadline));
    };
    let reason = match &error {
        DispatchError::HostBusy => Reason::HostBusy,
        // A host that is gone took its enclave's key with it.
        DispatchError::EnclaveChanged | DispatchError::Host(_) => Reason::EnclaveChanged,
    };
    tracing::warn!(%error, %host, dependency = "host", reason = reason.as_str(), "dispatch failed");
    match state.jobs.fail_dispatch(&job.job_id, sub, reason).await {
        // The host may have queued it after all and already finished it.
        Ok(()) | Err(StorageError::NotMigrating) => Err(ApiError::failed(reason)),
        Err(error) => Err(ApiError::storage("dynamodb", error.to_string())),
    }
}

/// The `sub`'s latest job. A `migrating` job past its deadline reads as `failed (timeout)`
/// without a write; a `migrated` one carries a fresh download URL.
async fn migration_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub): Path<String>,
) -> Result<Json<MigrationStatus>, ApiError> {
    let (_, job) = owned_job(&state, &headers, &sub).await?;
    let now = unix_now();
    let mut status = MigrationStatus {
        status: job.status,
        reason: job.reason,
        deadline: job.deadline,
        download_url: None,
        download_expires_at: None,
    };
    match job.status {
        Status::Migrating if job.deadline.is_some_and(|deadline| now > deadline) => {
            status.status = Status::Failed;
            status.reason = Some(Reason::Timeout);
        }
        Status::Migrated => {
            status.download_url = Some(
                state
                    .bucket
                    .presign_download(&job.job_id, state.presigned_url_ttl)
                    .await
                    .map_err(|error| ApiError::storage("s3", error.to_string()))?,
            );
            status.download_expires_at = Some(now + state.presigned_url_ttl.as_secs());
        }
        _ => {}
    }
    Ok(Json(status))
}

/// The answer to a migrate for a job that already left `created`.
fn already_claimed(
    job: &JobRecord,
    now: u64,
) -> Result<(StatusCode, Json<MigrateResponse>), ApiError> {
    match (job.status, job.deadline) {
        (Status::Migrating, Some(deadline)) if now <= deadline => Ok(accepted(deadline)),
        (Status::Migrating, _) => Err(ApiError::failed(Reason::Timeout)),
        (Status::Failed, _) => Err(ApiError::failed(job.reason.unwrap_or(Reason::Timeout))),
        (Status::Created | Status::Migrated, _) => Err(ApiError::invalid_state()),
    }
}

const fn accepted(deadline: u64) -> (StatusCode, Json<MigrateResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(MigrateResponse {
            status: Status::Migrating,
            deadline,
        }),
    )
}

/// The `sub`'s latest job, if the caller's device key is the one it was created with.
async fn owned_job<'a>(
    state: &AppState,
    headers: &HeaderMap,
    sub: &'a str,
) -> Result<(&'a str, JobRecord), ApiError> {
    let device_public_key = device_public_key(headers).ok_or_else(ApiError::invalid_device_key)?;
    let sub = valid_sub(sub)?;
    let job = state
        .jobs
        .latest_job(sub)
        .await
        .map_err(|error| ApiError::storage("dynamodb", error.to_string()))?
        .ok_or_else(ApiError::not_found)?;
    if job.device_public_key != device_public_key {
        return Err(ApiError::device_key_mismatch());
    }
    Ok((sub, job))
}

/// A trimmed `sub` that is not blank, too long or full of control characters.
fn valid_sub(sub: &str) -> Result<&str, ApiError> {
    let sub = sub.trim();
    if sub.is_empty() || sub.len() > MAX_SUB_LEN || sub.chars().any(char::is_control) {
        return Err(ApiError::invalid_sub());
    }
    Ok(sub)
}

/// The device key the auth proxy forwards; the API does not verify devices itself.
fn device_public_key(headers: &HeaderMap) -> Option<String> {
    let key = headers.get(DEVICE_KEY_THUMBPRINT)?.to_str().ok()?.trim();
    (!key.is_empty() && key.len() <= MAX_DEVICE_KEY_LEN).then(|| key.to_owned())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
