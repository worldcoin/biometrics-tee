use std::sync::Arc;

use di_dev_enclave_primitives::{self as enclave_primitives, HealthRequest};

use crate::state::EnclaveState;

/// Healthy while the worker lives; a dead worker exits the enclave, failing the next probe.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: HealthRequest,
) -> Result<(), enclave_primitives::Error> {
    state.check_worker();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::Ordering};

    use di_dev_enclave_primitives::HealthRequest;

    use super::handler;
    use crate::state::{EnclaveState, tests::FakeWorker};

    #[tokio::test]
    async fn health_checks_the_worker() {
        let worker = FakeWorker::default();
        let checks = Arc::clone(&worker.checks);
        let state = Arc::new(EnclaveState::new(Box::new(worker)));

        handler(state, HealthRequest).await.expect("healthy");

        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }
}
