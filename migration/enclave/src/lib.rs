//! Nitro enclave workload for the `DeepIdentifier` migration.
//!
//! Attests a per-boot channel key through the NSM, opens the PCPs apps seal to it, and seals the
//! migrated PCP back to the app. The pipeline in between echoes until it lands.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Nitro Secure Module attestation of the boot's channel key.
pub mod attestation;
/// The migration between opening and sealing.
pub mod pipeline;
/// Nitro hardware RNG verification.
pub mod rng;
/// Pontifex operations exposed to the host.
pub mod routes;
/// Pontifex server setup and lifecycle.
pub mod server;
/// Boot-scoped enclave state.
pub mod state;
#[cfg(test)]
mod test_support;

/// Runs CPU-bound work, such as opening a PCP, off the async workers. A panic exits the enclave:
/// it may have left keys or plaintext in an unknown state.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, di_migration_enclave_types::Error> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|_| {
            tracing::error!("blocking enclave task panicked");
            std::process::exit(1);
        })
    })
    .await
    .map_err(|_| di_migration_enclave_types::Error::Internal)
}
