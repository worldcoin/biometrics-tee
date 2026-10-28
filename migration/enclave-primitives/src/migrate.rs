use pontifex::Request;
use serde::{Deserialize, Serialize};

/// Maximum plaintext size of a migration diagnostic sealed to the device key.
pub const MAX_MIGRATION_DIAGNOSTIC_BYTES: usize = 64 * 1024;
/// Libsodium sealed-box overhead added to a migration diagnostic.
pub const MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES: usize = 48;
/// Maximum encrypted migration diagnostic accepted outside the enclave.
pub const MAX_SEALED_MIGRATION_DIAGNOSTIC_BYTES: usize =
    MAX_MIGRATION_DIAGNOSTIC_BYTES + MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES;

use crate::Error;

/// Requests the migration of one sealed PCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateRequest {
    /// The app's [`crate::pcp_payload`], sealed to this boot's channel key, as uploaded.
    pub blob: bytes::Bytes,
    /// Account the ownership proof was verified for; sealed into the new PCP.
    pub sub: String,
}

impl Request for MigrateRequest {
    const ROUTE_ID: &'static str = "/v1/migrate";
    type Response = Result<MigrateResponse, MigrateError>;
}

/// Successful migration with an optional encrypted worker debug report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// Tier 0 PCP sealed to the app's one-time response key.
    #[serde(with = "serde_bytes")]
    pub pcp: Vec<u8>,
    /// Worker JSON report encrypted to `device_public_key` on success.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub debug_report: Option<Vec<u8>>,
}

/// A migration failure and optional worker report encrypted to the device key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateError {
    /// Payload-free failure reason exposed to the host.
    pub error: Error,
    /// Sealed debug report JSON report encrypted to `device_public_key`.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub debug_report: Option<Vec<u8>>,
}

impl From<Error> for MigrateError {
    fn from(error: Error) -> Self {
        Self {
            error,
            debug_report: None,
        }
    }
}

impl std::fmt::Debug for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrateError")
            .field("error", &self.error)
            .field("has_debug_report", &self.debug_report.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::MigrateRequest;

    #[test]
    fn migrate_route_id_is_versioned_and_stable() {
        assert_eq!(MigrateRequest::ROUTE_ID, "/v1/migrate");
    }
}
