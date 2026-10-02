use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Requests the migration of one sealed PCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateRequest {
    /// The sealed PCP as uploaded by the app.
    pub blob: bytes::Bytes,
    /// Account the ownership proof was verified for; sealed into the new PCP.
    pub sub: String,
    /// The app's attested device key; sealed into the new PCP so only it can refresh.
    pub device_public_key: String,
}

impl Request for MigrateRequest {
    const ROUTE_ID: &'static str = "/v1/migrate";
    type Response = Result<MigrateResponse, Error>;
}

/// The migrated PCP, sealed back to the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// Echoed verbatim until the migration pipeline lands.
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
