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
mod keys;
mod migrate;
pub mod payload;

/// vsock port the enclave serves and the host dials; both sides ship together.
pub const PONTIFEX_PORT: u32 = 1000;

/// Pontifex channel domain the app seals PCPs under; both sides must agree on it.
pub const MIGRATION_CHANNEL_DOMAIN: &str = "di-migration/migrate_v1";

pub use error::Error;
pub use health::HealthRequest;
pub use keys::{GetEncryptionKeyRequest, KeyAttestation};
pub use migrate::{MigrateRequest, MigrateResponse};
