use pontifex::Request;
use serde::{Deserialize, Serialize};

/// Maximum plaintext size of a migration diagnostic sealed to the response key.
pub const MAX_MIGRATION_DIAGNOSTIC_BYTES: usize = 2 * 1024 * 1024;
/// Quantum-box 0.2 header, encapsulated key, and authentication tag.
pub const MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES: usize = 7 + 1120 + 16;
/// Maximum sealed migration diagnostic accepted outside the enclave.
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

/// Successful migration with an optional sealed migration debug report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// Tier 0 PCP sealed to the app's one-time response key.
    #[serde(with = "serde_bytes")]
    pub pcp: Vec<u8>,
    /// Migration JSON report sealed to the same response key as the PCP.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub debug_report: Option<Vec<u8>>,
}

/// A migration failure and optional migration report sealed to the request's response key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateError {
    /// Payload-free failure reason exposed to the host.
    pub error: Error,
    /// Migration JSON report sealed to the request's response key.
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
