use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
/// Bounds the subject we accept; real subjects are short opaque identifiers.
const MAX_SUB_LEN: usize = 255;

pub fn router(state: AppState) -> Router {
    let probes = Router::new()
        .route("/healtz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/init-migration", post(init_migration))
        .with_state(state.clone());

    Router::new().merge(probes).with_state(state)
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

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    let (db_result, sqs_result, s3_result) = tokio::join!(
        state.db.check_ready(),
        state.sqs.check_ready(),
        state.s3.check_ready()
    );

    if let Err(error) = &db_result {
        tracing::warn!(error = %format!("{error:#}"), dependency = "dynamodb", "readiness check failed");
    }
    if let Err(error) = &sqs_result {
        tracing::warn!(error = %format!("{error:#}"), dependency = "sqs", "readiness check failed");
    }
    if let Err(error) = &s3_result {
        tracing::warn!(error = %format!("{error:#}"), dependency = "s3", "readiness check failed");
    }
    if db_result.is_ok() && sqs_result.is_ok() && s3_result.is_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn init_migration(
    State(state): State<AppState>,
    Json(request): Json<InitMigrationRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let sub = request.sub.trim();
    if sub.is_empty() || sub.len() > MAX_SUB_LEN || sub.chars().any(char::is_control) {
        return Err((StatusCode::BAD_REQUEST, "invalid_sub"));
    }

    let verification = proof::VerificationRequest {
        challenge_id: request.challenge_id,
        challenge_type: state.verifier.config.challenge_type.clone(),
        credential_sub: sub.to_string(),
        proof: request.proof,
    };
    if let Err(error) = state.verifier.verify(verification).await {
        if !matches!(error, proof::ProofVerificationError::VerificationError) {
            tracing::error!(error = %error, credential_sub = %sub, "failed to verify the proof");
        }
        let status = match error {
            proof::ProofVerificationError::VerificationError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        return Err((status, error.as_str()));
    }

    let migration_id = Uuid::new_v4();
    let object_key = format!("pcp/{migration_id}");

    state
        .db
        .put_migration(&migration_id.to_string(), sub, &object_key)
        .await
        .map_err(|error| {
            tracing::error!(error = %format!("{error:#}"), %migration_id, "failed to record the migration");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        })?;

    let presigned_url = state.s3.presign_put(&object_key).await.map_err(|error| {
        tracing::error!(error = %format!("{error:#}"), %migration_id, "failed to presign the PCP upload URL");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    })?;
    let attestation = state.attestor.attest();

    Ok(Json(InitMigrationResponse {
        enclave_id: attestation.enclave_id,
        attestation: attestation.document,
        presigned_url,
    }))
}
