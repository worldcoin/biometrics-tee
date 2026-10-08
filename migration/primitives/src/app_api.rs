//! The Migration API's public HTTP API, called by the app.

use serde::{Deserialize, Serialize};

use crate::{EnclaveId, Reason, Status};

pub use crate::host_api::{ErrorBody, ErrorEnvelope};

/// The caller's device public key, set by the auth proxy in front of the API once it has
/// verified the device.
pub const DEVICE_KEY_THUMBPRINT: &str = "x-attested-key-thumbprint";

/// `POST /v1/init-migration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitMigrationRequest {
    /// The account to migrate; the ownership proof is over it.
    pub sub: String,
    /// Standard base64 ownership proof.
    pub proof: String,
    /// The challenge the proof was built for.
    pub challenge_id: String,
}

/// `200` body of `POST /v1/init-migration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitMigrationResponse {
    /// The enclave boot the PCP must be sealed to.
    pub enclave_id: EnclaveId,
    /// COSE attestation document, standard padded base64.
    pub attestation: String,
    /// Full X-Wing public key, standard padded base64.
    pub enclave_public_key: String,
    /// Presigned S3 URL the sealed PCP is uploaded to with `PUT`.
    pub upload_url: String,
    /// Unix seconds by which migrate must be called; later the app must init again.
    pub migrate_by: u64,
}

/// `POST /v1/migrations/{sub}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateRequest {
    /// The attested device key's `cnf.jwk`, serialized exactly as the app gives it to the orb.
    /// The enclave seals this string into the new PCP verbatim; its thumbprint must be the one
    /// the migration was started with.
    pub device_public_key: String,
}

/// `202` body of `POST /v1/migrations/{sub}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// Always `migrating`.
    pub status: Status,
    /// Unix seconds after which an unfinished job reads as `failed (timeout)`.
    pub deadline: u64,
}

/// `200` body of `GET /v1/migrations/{sub}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatus {
    /// The job's state; a `migrating` job past its deadline reads as `failed`.
    pub status: Status,
    /// Why it failed, once `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Unix seconds the job must finish by, once migrate was called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// Presigned S3 URL of the result, sealed to the app, once `migrated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    /// Unix seconds `download_url` stops working; poll again for a fresh one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_expires_at: Option<u64>,
}

/// Machine-readable error codes. A migrate whose dispatch failed answers with the [`Reason`]
/// as its code.
pub mod codes {
    /// The device key header is missing or invalid.
    pub const INVALID_DEVICE_KEY: &str = "invalid_device_key";
    /// No host has room; retry after `Retry-After`.
    pub const AT_CAPACITY: &str = "at_capacity";
    /// The `sub` already has an active migration; poll it instead.
    pub const MIGRATION_IN_PROGRESS: &str = "migration_in_progress";
    /// The `sub` has no migration.
    pub const NOT_FOUND: &str = "not_found";
    /// The device key does not match the one stored at init.
    pub const DEVICE_KEY_MISMATCH: &str = "device_key_mismatch";
    /// Migrate was called before the sealed PCP was uploaded.
    pub const NOT_UPLOADED: &str = "not_uploaded";
    /// Migrate came after the upload window; the app must init again.
    pub const EXPIRED: &str = "expired";
    /// The migration already finished.
    pub const INVALID_STATE: &str = "invalid_state";
}
