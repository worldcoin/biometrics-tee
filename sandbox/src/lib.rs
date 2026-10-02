//! Sandboxed worker support for the DI migration enclaves.
//!
//! The enclave receives one verified executable over vsock at boot, launches it under Minijail
//! with an embedded seccomp policy, and exchanges length-framed messages with it over FD 3.
//! Payloads are the caller's: this crate never decodes worker messages.

#![deny(clippy::all, missing_docs)]

mod bundle;
mod channel;
mod config;
pub mod host;
#[cfg(target_os = "linux")]
mod process;
mod transport;

pub use bundle::{
    Error, MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES, Manifest, VerifiedRuntime, WORKER_PATH, package,
    receive,
};
pub use channel::{ChannelConfig, ChannelError};
pub use config::BootstrapConfig;
#[cfg(target_os = "linux")]
pub use process::{SandboxConfig, WORKER_UID, Worker, WorkerError};

/// vsock port on which the enclave accepts the worker bundle, once, from the parent.
pub const BOOTSTRAP_PORT: u32 = 1001;
