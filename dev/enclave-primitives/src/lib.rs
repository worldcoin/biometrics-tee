//! The vsock contract between the dev host and its enclave.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod health;
mod migrate;

/// vsock port the enclave serves and the host dials; both sides ship together.
pub const PONTIFEX_PORT: u32 = 1000;

pub use error::Error;
pub use health::HealthRequest;
pub use migrate::{MigrateRequest, MigrateResponse};
