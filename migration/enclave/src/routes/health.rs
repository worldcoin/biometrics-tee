use std::sync::Arc;

use di_migration_enclave_primitives::{self as enclave_primitives, HealthRequest};

use crate::state::EnclaveState;

pub async fn handler(
    _: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_primitives::Error> {
    Ok(())
}
