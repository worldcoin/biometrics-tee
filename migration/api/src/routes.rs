use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use di_migration_primitives::JobId;
use di_migration_storage::schema::pcp_key;
use serde::{Deserialize, Serialize};

use crate::{AppState, error::ApiError, fleet::FleetLoad};
/// Bounds the subject we accept; real subjects are short opaque identifiers.
const MAX_SUB_LEN: usize = 255;

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

#[derive(Deserialize)]
struct InitMigrationRequest {
    /// Subject of the user being migrated.
    sub: String,
    /// Standard base64 ownership proof.
    proof: String,
    /// Challenge ID.
    challenge_id: String,
}

#[derive(Serialize)]
struct InitMigrationResponse {
    enclave_id: String,
    /// COSE attestation document, standard padded base64.
    attestation: String,
    /// Presigned S3 URL the client uploads the PCP to with `PUT`.
    presigned_url: String,
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
    let (db_result, bucket_result) =
        tokio::join!(state.db.check_ready(), state.bucket.check_ready());

    if let Err(error) = &db_result {
        tracing::warn!(error = %format!("{error:#}"), dependency = "dynamodb", "readiness check failed");
    }
    if let Err(error) = &bucket_result {
        tracing::warn!(%error, dependency = "s3", "readiness check failed");
    }
    if db_result.is_ok() && bucket_result.is_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn init_migration(
    State(state): State<AppState>,
    Json(request): Json<InitMigrationRequest>,
) -> Result<Json<InitMigrationResponse>, ApiError> {
    let sub = request.sub.trim();
    if sub.is_empty() || sub.len() > MAX_SUB_LEN || sub.chars().any(char::is_control) {
        return Err(ApiError::invalid_sub());
    }

    let verification = proof::VerificationRequest {
        challenge_id: request.challenge_id,
        challenge_type: state.verifier.config.challenge_type.clone(),
        credential_sub: sub.to_string(),
        proof: request.proof,
    };
    state
        .verifier
        .verify(verification)
        .await
        .map_err(|error| ApiError::proof(&error))?;

    let job_id = JobId::new();
    state
        .db
        .put_migration(job_id.as_str(), sub, &pcp_key(&job_id))
        .await
        .map_err(|error| ApiError::storage("dynamodb", format!("{error:#}")))?;

    let presigned_url = state
        .bucket
        .presign_upload(&job_id, state.presigned_url_ttl)
        .await
        .map_err(|error| ApiError::storage("s3", error.to_string()))?;
    let attestation = state.attestor.attest();

    Ok(Json(InitMigrationResponse {
        enclave_id: attestation.enclave_id,
        attestation: attestation.document,
        presigned_url,
    }))
}
