//! Worker launch and enclave serving on Linux.

use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use di_dev_enclave::{
    bootstrap::{self, BootWorker},
    server,
    state::EnclaveState,
};
use di_dev_enclave_types::PONTIFEX_PORT;
use di_sandbox::{ConnectionConfig, ConnectionError, SandboxConfig, Worker};
use tracing_subscriber::EnvFilter;

/// Receives and launches the worker while the process is single-threaded, then serves.
pub(super) fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    std::panic::set_hook(Box::new(|_| {
        tracing::error!("enclave panicked");
    }));

    let mut boot = bootstrap::receive().context("worker bundle provisioning failed")?;
    let (worker, ready) = Worker::spawn(
        &boot.runtime.binary,
        SandboxConfig {
            root: boot.runtime.root.path(),
            address_space_bytes: boot.address_space_bytes,
            max_threads: boot.max_threads,
        },
        ConnectionConfig::default(),
        worker_failed,
    )
    .context("sandboxed worker launch failed")?;
    if !di_worker_protocol::protobuf::decode_ready(&ready) {
        bail!("worker announced an unsupported protocol version");
    }
    worker.check_alive();

    // The verified runtime root must outlive the worker.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start enclave executor")?
        .block_on(serve(&mut boot, worker))
}

/// A dead worker cannot be replaced within a boot; init tears the enclave down on exit.
fn worker_failed(error: ConnectionError) -> ! {
    tracing::error!(dependency = "worker", %error, "terminal worker failure; exiting enclave");
    std::process::exit(1)
}

/// Acknowledges the bundle once the worker is ready, then accepts host requests.
async fn serve(boot: &mut BootWorker, worker: Worker) -> anyhow::Result<()> {
    let state = Arc::new(EnclaveState::new(Box::new(Mutex::new(worker))));
    state.check_worker();
    boot.acknowledge()?;

    tracing::info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");
    // Err exits non-zero so the provisioner restarts the enclave rather than idling without a server.
    server::start(state, PONTIFEX_PORT)
        .await
        .inspect_err(|error| {
            tracing::error!(%error, "enclave Pontifex server stopped");
        })
}
