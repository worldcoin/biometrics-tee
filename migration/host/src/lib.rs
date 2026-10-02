//! Untrusted host for the `DeepIdentifier` migration enclave: relays the enclave's key
//! attestation and, in later steps, queues and runs migration jobs.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod app_state;
#[cfg(test)]
mod test_support;

pub mod config;
pub mod enclave;
pub mod error;
pub mod readiness;
pub mod routes;
pub mod server;

pub use app_state::AppState;
