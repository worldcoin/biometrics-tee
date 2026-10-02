use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Requests this boot's identity, which the host relays to the API at init.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IdentityRequest;

impl Request for IdentityRequest {
    const ROUTE_ID: &'static str = "/v1/identity";
    type Response = Result<Identity, Error>;
}

/// The enclave's boot-scoped identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Changes on every boot, so a job sealed to a previous boot is detectable.
    pub enclave_id: String,
    /// Attestation document committing to `public_key`.
    #[serde(with = "serde_bytes")]
    pub attestation: Vec<u8>,
    /// Key the app seals its PCP to.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::IdentityRequest;

    #[test]
    fn identity_route_id_is_versioned_and_stable() {
        assert_eq!(IdentityRequest::ROUTE_ID, "/v1/identity");
    }
}
