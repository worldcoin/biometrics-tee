//! The vsock contract between the migration host and its enclave. Shares nothing with the
//! `dev` workload: a shared type would rotate its enclave's PCR0.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod health;
mod identity;
mod migrate;

/// vsock port the enclave serves and the host dials; both sides ship together.
pub const PONTIFEX_PORT: u32 = 1000;

pub use error::Error;
pub use health::HealthRequest;
pub use identity::{Identity, IdentityRequest};
pub use migrate::{MigrateRequest, MigrateResponse};
