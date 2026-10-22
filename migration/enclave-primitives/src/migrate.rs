use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Requests the migration of one sealed PCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateRequest {
    /// The app's [`crate::pcp_payload`], sealed to this boot's channel key, as uploaded.
    pub blob: bytes::Bytes,
    /// Account the ownership proof was verified for; sealed into the new PCP.
    pub sub: String,
    /// Standard-Base64, 32-byte device public key used to encrypt the output PCP.
    pub device_public_key: String,
}

impl Request for MigrateRequest {
    const ROUTE_ID: &'static str = "/v1/migrate";
    type Response = Result<MigrateResponse, Error>;
}

/// The encrypted Tier 0 PCP, sealed back to the app's one-time response key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// Raw Tier 0 bytes only the app can open; the host just stores them.
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
    /// An encrypted diagnostic on failure; then `blob` is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SealedMigrationError>,
}

/// A coarse failure reason and diagnostic encrypted to the personal-custody public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedMigrationError {
    /// Payload-free reason the host uses to mark the job failed.
    pub reason: Error,
    /// Libsodium sealed box containing UTF-8 diagnostic text, encrypted to `device_public_key`.
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
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
