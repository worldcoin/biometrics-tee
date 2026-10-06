//! Nitro enclave workload for the `DeepIdentifier` migration.
//!
//! Attests a per-boot channel key through the NSM. Migrate still echoes the sealed blob until the
//! pipeline lands.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Nitro Secure Module attestation of the boot's channel key.
pub mod attestation;
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
