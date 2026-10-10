//! Worker isolation precedes executor threads and key generation, as in Flamingo.
use crate::{
    State,
    attestation::{self, NsmAttestor},
    bootstrap,
    engine::SandboxEngine,
    rng,
};
use anyhow::Context;
use biometrics_sandbox::{ConnectionConfig, ConnectionError, SandboxConfig, Worker};
use selfie_enrollment_enclave_types::{
    AssignmentRequest, Error, ExtractRequest, HealthRequest, PONTIFEX_PORT,
};
use selfie_enrollment_sealed_types::WorkerIdentity;
use std::{sync::Arc, time::Duration};
pub fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| tracing::error!("enrollment enclave panicked")));
    rng::verify_nsm_hwrng_current()?;
    let mut boot = bootstrap::receive()?;
    let (worker, ready) = Worker::spawn(
        &boot.runtime.binary,
        SandboxConfig {
            root: boot.runtime.root.path(),
            address_space_bytes: boot.address_space_bytes,
            max_threads: boot.max_threads,
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
    let identity = WorkerIdentity {
        profile: selfie_enrollment_api_types::PROFILE.into(),
        executable_sha384: boot.runtime.sha384.clone(),
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            attestation::connect().await?;
            let attestor = NsmAttestor {
                user_data: identity.encode()?.to_vec(),
            };
            let mut state = State::new(
                Arc::new(attestor),
                Box::new(SandboxEngine { worker, next_id: 1 }),
                identity,
            )?;
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
            boot.acknowledge()?;
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
fn worker_failed(_: ConnectionError) -> ! {
    tracing::error!("terminal biometric worker failure");
    std::process::exit(1)
}
