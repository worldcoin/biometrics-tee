//! Worker launch and enclave serving on Linux.

use std::{
    path::Path,
    sync::{Arc, LazyLock, Mutex},
};

use anyhow::{Context, bail};
use di_dev_enclave::{server, state::EnclaveState};
use di_dev_enclave_primitives::PONTIFEX_PORT;
use tabernaculum::{
    ConnectionConfig, ConnectionError, Limits, Policy, SandboxConfig, Worker,
    bundle::{
        BootstrapConfig,
        enclave::{self, Bootstrap},
    },
};
use tracing_subscriber::EnvFilter;

/// The reviewed default seccomp policy, unchanged.
static POLICY: LazyLock<Policy> = LazyLock::new(Policy::default_worker);

/// Receives and launches the worker while the process is single-threaded, then serves.
pub(super) fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| {
        tracing::error!("enclave panicked");
    }));

    let boot = enclave::accept(&BootstrapConfig::default(), Path::new(enclave::STAGING_DIR))
        .context("worker bundle provisioning failed")?;
    let runtime = boot.runtime();
    tracing::info!(release_id = %runtime.release_id, worker_sha384 = %runtime.sha384, "worker executable provisioned");
    let (worker, ready) = Worker::spawn(
        &runtime.binary,
        SandboxConfig {
            root: runtime.root.path(),
            limits: Limits::default(),
            policy: &POLICY,
        },
        ConnectionConfig::default(),
        worker_failed,
    )
    .context("sandboxed worker launch failed")?;
    if !di_worker_protocol::protobuf::decode_ready(&ready) {
        bail!("worker announced an unsupported protocol version");
    }
    worker.check_alive();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start enclave executor")?
        .block_on(serve(boot, worker))
}

/// A dead worker cannot be replaced within a boot; init tears the enclave down on exit.
fn worker_failed(error: ConnectionError) -> ! {
    tracing::error!(dependency = "worker", %error, "terminal worker failure; exiting enclave");
    std::process::exit(1)
}

/// Acknowledges the bundle once the worker is ready, then accepts host requests.
async fn serve(boot: Bootstrap, worker: Worker) -> anyhow::Result<()> {
    let state = Arc::new(EnclaveState::new(Box::new(Mutex::new(worker))));
    state.check_worker();
    // The verified runtime root must outlive the worker, which the server owns.
    let _runtime = boot
        .acknowledge()
        .context("failed to acknowledge worker startup")?;

    tracing::info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");
    // Err exits non-zero so the provisioner restarts the enclave rather than idling without a server.
    server::start(state, PONTIFEX_PORT)
        .await
        .inspect_err(|error| {
            tracing::error!(%error, "enclave Pontifex server stopped");
        })
}
