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
    /// The app's attested device key as its RFC 7638 canonical JWK; sealed into the new PCP, as
    /// the orb seals it, so only that device can refresh.
    pub device_public_key: String,
}

impl Request for MigrateRequest {
    const ROUTE_ID: &'static str = "/v1/migrate";
    type Response = Result<MigrateResponse, Error>;
}

/// The migrated PCP, sealed back to the app's one-time response key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// A [`crate::pcp_payload`] only the app can open; the host just stores it.
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
