use std::sync::Arc;

use di_dev_enclave_primitives::PONTIFEX_PORT;
use di_dev_host::{AppState, enclave::PontifexEnclaveClient};

/// The enclave's CID, which `nitro-cli` assigns at boot, so it cannot be a constant.
///
/// # Panics
///
/// Panics when `ENCLAVE_CID` is unset or does not parse; a host that cannot reach its enclave
/// must not start.
fn enclave_cid() -> u32 {
    std::env::var("ENCLAVE_CID")
        .expect("ENCLAVE_CID environment variable is not set")
        .parse()
        .expect("ENCLAVE_CID environment variable is not a valid u32")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let cid = enclave_cid();
    tracing::info!(
        enclave_cid = cid,
        enclave_port = PONTIFEX_PORT,
        "Starting API"
    );

    let enclave_client = Arc::new(PontifexEnclaveClient::new(cid, PONTIFEX_PORT));

    di_dev_host::server::start(AppState::new(enclave_client)).await
}
