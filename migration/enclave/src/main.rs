use std::sync::Arc;

use di_migration_enclave::{server, state::EnclaveState};
use di_migration_enclave_types::PONTIFEX_PORT;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Err exits non-zero so the carrier restarts the enclave rather than idling without a server.
    server::start(Arc::new(EnclaveState::boot()), PONTIFEX_PORT)
        .await
        .inspect_err(|error| {
            tracing::error!(%error, "enclave Pontifex server stopped");
        })
}
