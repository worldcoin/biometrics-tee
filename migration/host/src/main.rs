use std::sync::Arc;

use clap::Parser;
use di_migration_host::{AppState, config::Config, enclave::PontifexEnclaveClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let config = Config::parse();
    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        config.enclave_cid,
        config.enclave_port,
    ));

    di_migration_host::server::start(config.port, AppState::new(enclave_client, config.host_ip))
        .await
}
