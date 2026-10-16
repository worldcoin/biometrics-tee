use std::sync::Arc;

use anyhow::{Context, anyhow};
use di_migration_enclave::{
    attestation::{self, NsmAttestor},
    kms::KeyWrapper,
    rng, server,
    state::EnclaveState,
};
use di_migration_enclave_primitives::PONTIFEX_PORT;
use pontifex::SecureModule;
use tracing_subscriber::EnvFilter;

// Err exits non-zero so the carrier restarts the enclave rather than idling without a server.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // The boot key must come from hardware entropy.
    rng::verify_nsm_hwrng_current().context("Nitro hardware RNG is not configured")?;
    attestation::connect()
        .await
        .context("Nitro Secure Module is unavailable")?;
    let mut state =
        EnclaveState::from_env(Arc::new(NsmAttestor)).context("failed to boot enclave state")?;
    match std::env::var("PCP_KMS_KEY_ARN") {
        Ok(arn) => {
            let region =
                std::env::var("PCP_KMS_REGION").context("measured KMS region is missing")?;
            state.set_key_wrapper(
                KeyWrapper::from_parent(arn, region)
                    .context("invalid measured KMS configuration")?,
            );
            tracing::info!("PCP key wrapping configured");
        }
        Err(std::env::VarError::NotPresent) => tracing::info!("PCP key wrapping is not configured"),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("invalid measured KMS configuration")
        }
    }
    let refresh = state.start_attestation_refresh();

    let document = SecureModule::global()
        .attest(None::<Vec<u8>>, None::<Vec<u8>>, None::<Vec<u8>>)
        .context("failed to read the boot measurements")?;
    attestation::log_boot_measurements(&document);

    tokio::select! {
        result = server::start(Arc::new(state), PONTIFEX_PORT) => {
            result.inspect_err(|error| tracing::error!(%error, "enclave Pontifex server stopped"))
        }
        result = refresh => Err(anyhow!("channel key attestation refresh stopped: {result:?}")),
    }
}
