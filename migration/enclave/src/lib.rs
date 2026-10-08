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
