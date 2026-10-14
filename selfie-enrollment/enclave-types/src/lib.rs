//! Ciphertext-only host/enclave RPC contract.
use pontifex::Request;
pub use selfie_enrollment_api_types::ErrorCode as Error;
use serde::{Deserialize, Serialize};
pub const PONTIFEX_PORT: u32 = 1000;
#[derive(Serialize, Deserialize)]
pub struct KeyAttestation {
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
pub struct AssignmentRequest;
impl Request for AssignmentRequest {
    const ROUTE_ID: &'static str = "/selfie-enrollment/v1/assignment";
    type Response = Result<KeyAttestation, Error>;
}
#[derive(Serialize, Deserialize)]
pub struct HealthRequest;
impl Request for HealthRequest {
    const ROUTE_ID: &'static str = "/selfie-enrollment/v1/health";
    type Response = Result<(), Error>;
}
#[derive(Serialize, Deserialize)]
pub struct ExtractRequest {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
pub struct ExtractResponse {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}
impl Request for ExtractRequest {
    const ROUTE_ID: &'static str = "/selfie-enrollment/v1/extract";
    type Response = Result<ExtractResponse, Error>;
}
