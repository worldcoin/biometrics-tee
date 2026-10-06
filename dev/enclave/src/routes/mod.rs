//! Pontifex operation routing.

use std::sync::Arc;

use di_dev_enclave_types::{HealthRequest, MigrateRequest};
use pontifex::Router;

mod health;
mod migrate;

use crate::state::EnclaveState;

/// Builds the router with all enclave operations.
pub(crate) fn router(state: Arc<EnclaveState>) -> Router<Arc<EnclaveState>> {
    Router::with_state(state)
        .route::<HealthRequest, _, _>(health::handler)
        .route::<MigrateRequest, _, _>(migrate::handler)
}

#[cfg(test)]
mod tests {
    use super::router;
    use crate::state::tests::state;

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(state());
    }
}
