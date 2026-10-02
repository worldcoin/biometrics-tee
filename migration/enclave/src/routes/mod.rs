//! Pontifex operation routing.

use std::sync::Arc;

use di_migration_enclave_types::{GetEncryptionKeyRequest, HealthRequest, MigrateRequest};
use pontifex::Router;

mod encryption_key;
mod health;
mod migrate;

use crate::state::EnclaveState;

/// Builds the router with all enclave operations.
pub(crate) fn router(state: Arc<EnclaveState>) -> Router<Arc<EnclaveState>> {
    Router::with_state(state)
        .route::<HealthRequest, _, _>(health::handler)
        .route::<GetEncryptionKeyRequest, _, _>(encryption_key::handler)
        .route::<MigrateRequest, _, _>(migrate::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::router;
    use crate::state::EnclaveState;

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(Arc::new(
            EnclaveState::boot().expect("should generate a key"),
        ));
    }
}
