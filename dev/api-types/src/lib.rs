//! The HTTP contract between the dev client and its host.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod codes;

mod error;
mod migrations;

pub use error::{ErrorBody, ErrorEnvelope};
pub use migrations::*;
