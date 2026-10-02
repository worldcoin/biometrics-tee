use std::sync::Arc;

use di_migration_enclave_types::{self as enclave_types, HealthRequest};

use crate::state::EnclaveState;

pub async fn handler(_: Arc<EnclaveState>, _: HealthRequest) -> Result<(), enclave_types::Error> {
    Ok(())
}
