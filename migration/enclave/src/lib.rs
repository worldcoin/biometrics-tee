//! Nitro enclave workload for the `DeepIdentifier` migration.
//!
//! Mock: echoes the sealed blob and serves a stub identity until the pipeline and attestation land.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Pontifex operations exposed to the host.
pub mod routes;
/// Pontifex server setup and lifecycle.
pub mod server;
/// Boot-scoped enclave state.
pub mod state;
