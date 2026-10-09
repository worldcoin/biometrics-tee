use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Requests the migration of one PCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateRequest {
    /// The decompressed PCP, relayed verbatim.
    pub pcp: bytes::Bytes,
}

impl Request for MigrateRequest {
    const ROUTE_ID: &'static str = "/v1/migrate";
    type Response = Result<MigrateResponse, Error>;
}

/// The migrated PCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResponse {
    /// The migrated PCP, echoed verbatim until the pipeline runs in the sandbox.
    #[serde(with = "serde_bytes")]
    pub pcp: Vec<u8>,
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
