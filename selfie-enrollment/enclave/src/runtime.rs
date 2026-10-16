//! Worker isolation precedes executor threads and key generation, as in Flamingo.
use crate::{
    State,
    attestation::{self, NsmAttestor},
    engine::SandboxEngine,
    rng,
};
use anyhow::Context;
use selfie_enrollment_enclave_types::{
    AssignmentRequest, ExtractRequest, HealthRequest, PONTIFEX_PORT,
};
use std::{
    path::Path,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tabernaculum::{
    ConnectionConfig, ConnectionError, Limits, Policy, SandboxConfig, Worker,
    bundle::{BootstrapConfig, enclave},
};
/// The reviewed default seccomp policy, unchanged.
static POLICY: LazyLock<Policy> = LazyLock::new(Policy::default_worker);
pub fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| tracing::error!("enrollment enclave panicked")));
    rng::verify_nsm_hwrng_current()?;
    let boot = enclave::accept(&BootstrapConfig::default(), Path::new(enclave::STAGING_DIR))
        .context("worker bundle verification failed")?;
    let runtime = boot.runtime();
    tracing::info!(release_id = %runtime.release_id, "worker executable provisioned");
    let (worker, ready) = Worker::spawn(
        &runtime.binary,
        SandboxConfig {
            root: runtime.root.path(),
            limits: Limits::default(),
            policy: &POLICY,
        },
        ConnectionConfig {
            request_timeout: Duration::from_secs(30),
            max_request_bytes: selfie_enrollment_api_types::MAX_REQUEST_BYTES,
            max_response_bytes: 256 * 1024,
            ..Default::default()
        },
        worker_failed,
    )?;
    anyhow::ensure!(
        biometric_engines_protocol::protobuf::decode_ready(&ready),
        "unsupported worker protocol"
    );
    worker.check_alive();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            attestation::connect().await?;
            let attestor = NsmAttestor;
            let mut state = State::new(Arc::new(attestor), Box::new(SandboxEngine::new(worker)))?;
            let refresh = state.refresh();
            let state = Arc::new(state);
            let document = pontifex::SecureModule::global().attest(
                None::<Vec<u8>>,
                None::<Vec<u8>>,
                None::<Vec<u8>>,
            )?;
            anyhow::ensure!(
                !attestation::has_zeroed_measurements(&document),
                "debug enclaves are not supported"
            );
            attestation::log_boot_measurements(&document);
            state.health()?;
            // The verified runtime root must outlive the worker, which the router owns.
            let _runtime = boot
                .acknowledge()
                .context("failed to acknowledge worker startup")?;
            let router = pontifex::Router::with_state(state)
                .route::<HealthRequest, _, _>(|s: Arc<State>, _: HealthRequest| async move {
                    s.health()
                })
                .route::<AssignmentRequest, _, _>(
                    |s: Arc<State>, _: AssignmentRequest| async move { s.assignment().await },
                )
                .route::<ExtractRequest, _, _>(|s: Arc<State>, r: ExtractRequest| async move {
                    s.extract(r).await
                });
            tokio::select! {
                result = router.serve(PONTIFEX_PORT) => result.context("enrollment server stopped"),
                _ = refresh => Err(anyhow::anyhow!("attestation refresh stopped")),
            }
        })
}
/// `ConnectionError` is payload-free, so logging it exposes no biometric data.
fn worker_failed(error: ConnectionError) -> ! {
    tracing::error!(dependency = "worker", %error, "terminal biometric worker failure; exiting enclave");
    std::process::exit(1)
}
