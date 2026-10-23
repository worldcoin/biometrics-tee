//! Nitro enclave workload for the `DeepIdentifier` migration.
//!
//! Attests a per-boot channel key through the NSM, opens the PCPs apps seal to it, and seals the
//! PCP back to the app. A sandboxed biometric worker received from the parent runs the migration
//! pipeline and returns the fresh biometric material used to build the output PCP.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Nitro Secure Module attestation of the boot's channel key.
pub mod attestation;
/// KMS encryption of per-package private recipient keys.
pub mod kms;
/// Fresh PCP recipients and KMS encryption of their private keys.
pub mod pcp_keys;
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
/// The sandboxed biometric worker.
pub mod worker;
