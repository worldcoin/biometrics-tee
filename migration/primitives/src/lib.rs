//! The migration's domain types and the host's internal API contract, shared by the Migration
//! API and the host. Plain data only: no AWS, no Pontifex.
//!
//! The enclave must not depend on this crate: any change here would otherwise rotate its PCR0.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod enclave;
pub mod host_api;
pub mod job;

pub use enclave::EnclaveId;
pub use job::{JobId, Reason, Status};
