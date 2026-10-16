//! Nitro enclave workload for the dev migration setup: no attestation, no keys, no decryption.
//! The migration pipeline runs in a sandboxed worker received from the parent at boot.

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
