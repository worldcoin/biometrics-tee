//! The migration's shared storage: the PCP bucket and the job table, with the row and key
//! schema the Migration API and the host both use, so neither can drift from the other.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod bucket;
mod error;
pub mod schema;
mod table;

pub use bucket::PcpBucket;
pub use error::StorageError;
pub use table::JobTable;
