//! The Migration API's public HTTP API, called by the app.

use serde::{Deserialize, Serialize};

use crate::EnclaveId;

pub use crate::host_api::{ErrorBody, ErrorEnvelope};

/// Carries the caller's device public key while device auth is mocked; the real verifier
/// replaces it with an integrity token and a request signature.
pub const DEVICE_PUBLIC_KEY_HEADER: &str = "x-device-public-key";

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

/// Machine-readable error codes.
pub mod codes {
    /// The device key is missing or invalid.
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    /// No host has room; retry after `Retry-After`.
    pub const AT_CAPACITY: &str = "at_capacity";
    /// The `sub` already has an active migration; poll it instead.
    pub const MIGRATION_IN_PROGRESS: &str = "migration_in_progress";
}
